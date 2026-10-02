/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useEffect, useRef, useCallback } from 'react';
import { onAuthStateChanged, signInWithPopup, signOut, User } from 'firebase/auth';
import {
  collection,
  doc,
  setDoc,
  deleteDoc,
  onSnapshot,
  query,
  orderBy,
  serverTimestamp
} from 'firebase/firestore';
import { auth, db, googleProvider, handleFirestoreError, OperationType } from './firebase';
import { encryptPassword, decryptPassword } from './crypto';

interface RawVaultItem {
  id: string;
  name: string;
  password: string; // encrypted blob: salt:iv:cipher
  time: string;
  userId?: string;
  isLocal?: boolean;
  createdAt?: { toMillis?: () => number } | number;
}

interface DecryptedItem {
  id: string;
  name: string;
  password: string;
  time: string;
  isLocal?: boolean;
}

interface AuthWarningState {
  domain: string;
  projectId: string;
  settingsUrl: string;
}

const LOCAL_STORAGE_KEY = 'vault_local_passwords';

function getLocalVaultItems(): RawVaultItem[] {
  try {
    const raw = localStorage.getItem(LOCAL_STORAGE_KEY);
    if (!raw) return [];
    return JSON.parse(raw);
  } catch {
    return [];
  }
}

function saveLocalVaultItems(items: RawVaultItem[]) {
  try {
    localStorage.setItem(LOCAL_STORAGE_KEY, JSON.stringify(items));
  } catch (e) {
    console.warn('Failed to save to local storage', e);
  }
}

interface GeneratorConfig {
  len: number;
  upper: boolean;
  lower: boolean;
  nums: boolean;
  syms: boolean;
  similar: boolean;
  ambig: boolean;
  norepeat: boolean;
  start: boolean;
  preset: string;
}

const SETS = {
  upper: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
  lower: 'abcdefghijklmnopqrstuvwxyz',
  nums: '0123456789',
  syms: '!@#$%^&*-_=+?.,:;~'
};
const SIMILAR = 'O0oIl1|';
const BRACKETS = '(){}[]<>\'"`/\\';

const PRESETS: Record<string, Partial<GeneratorConfig> | null> = {
  custom: null,
  strong: { len: 20, upper: true, lower: true, nums: true, syms: true, similar: false, ambig: false, norepeat: false, start: false },
  easy: { len: 14, upper: true, lower: true, nums: true, syms: false, similar: true, ambig: true, norepeat: false, start: false },
  pin: { len: 6, upper: false, lower: false, nums: true, syms: false, similar: false, ambig: false, norepeat: false, start: false },
  letters: { len: 16, upper: true, lower: true, nums: false, syms: false, similar: false, ambig: false, norepeat: false, start: true }
};

function randInt(max: number): number {
  const buf = new Uint32Array(1);
  const limit = Math.floor(0x100000000 / max) * max;
  do {
    crypto.getRandomValues(buf);
  } while (buf[0] >= limit);
  return buf[0] % max;
}

function clean(chars: string, noSimilar: boolean, noAmbig: boolean): string {
  let res = chars;
  if (noSimilar) res = [...res].filter(c => !SIMILAR.includes(c)).join('');
  if (noAmbig) res = [...res].filter(c => !BRACKETS.includes(c)).join('');
  return res;
}

function formatCurrentTime(): string {
  const d = new Date();
  const months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
  const day = String(d.getDate()).padStart(2, '0');
  const month = months[d.getMonth()];
  const year = d.getFullYear();
  const hours = String(d.getHours()).padStart(2, '0');
  const mins = String(d.getMinutes()).padStart(2, '0');
  return `${day} ${month} ${year}, ${hours}:${mins}`;
}

export default function App() {
  const [currentUser, setCurrentUser] = useState<User | null>(null);
  const [authReady, setAuthReady] = useState(false);

  // Generator Options State
  const [len, setLen] = useState<number>(16);
  const [preset, setPreset] = useState<string>('custom');
  const [upper, setUpper] = useState<boolean>(true);
  const [lower, setLower] = useState<boolean>(true);
  const [nums, setNums] = useState<boolean>(true);
  const [syms, setSyms] = useState<boolean>(true);
  const [similar, setSimilar] = useState<boolean>(false);
  const [ambig, setAmbig] = useState<boolean>(false);
  const [norepeat, setNorepeat] = useState<boolean>(false);
  const [start, setStart] = useState<boolean>(false);

  // Output & Strength State
  const [password, setPassword] = useState<string>('');
  const [msg, setMsg] = useState<string>('');
  const [strengthText, setStrengthText] = useState<string>('Strength: –');
  const [barWidth, setBarWidth] = useState<string>('0%');
  const [barColor, setBarColor] = useState<string>('var(--weak)');

  // History State
  const [masterPassword, setMasterPassword] = useState<string>('');
  const [hname, setHname] = useState<string>('');
  const [hmsg, setHmsg] = useState<string>('');
  const [rawHistory, setRawHistory] = useState<RawVaultItem[]>([]);
  const [decryptedHistory, setDecryptedHistory] = useState<DecryptedItem[]>([]);
  const [historyRevealed, setHistoryRevealed] = useState<boolean>(false);
  const [authWarning, setAuthWarning] = useState<AuthWarningState | null>(null);
  const [copiedDomain, setCopiedDomain] = useState<boolean>(false);

  const isRemoteSyncRef = useRef<boolean>(false);
  const syncTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  // Monitor Auth state
  useEffect(() => {
    const unsubscribe = onAuthStateChanged(auth, user => {
      setCurrentUser(user);
      setAuthReady(true);
    });
    return () => unsubscribe();
  }, []);

  // Compute Password Strength
  const rateStrength = useCallback((lenVal: number, poolSize: number) => {
    if (poolSize <= 0 || lenVal <= 0) {
      setStrengthText('Strength: –');
      setBarWidth('0%');
      return;
    }
    const bits = lenVal * Math.log2(poolSize);
    let label = 'Weak';
    let color = 'var(--weak)';
    if (bits < 40) {
      label = 'Weak';
      color = 'var(--weak)';
    } else if (bits < 60) {
      label = 'Okay';
      color = 'var(--mid)';
    } else if (bits < 90) {
      label = 'Strong';
      color = 'var(--accent)';
    } else {
      label = 'Very strong';
      color = 'var(--accent)';
    }
    const pct = Math.min(100, (bits / 110) * 100);
    setBarWidth(`${pct}%`);
    setBarColor(color);
    setStrengthText(`Strength: ${label} (${Math.round(bits)} bits)`);
  }, []);

  // Generate Password
  const generate = useCallback(
    (
      currentLen = len,
      cUpper = upper,
      cLower = lower,
      cNums = nums,
      cSyms = syms,
      cSimilar = similar,
      cAmbig = ambig,
      cNorepeat = norepeat,
      cStart = start
    ) => {
      const activeGroups: string[] = [];
      if (cUpper) activeGroups.push(clean(SETS.upper, cSimilar, cAmbig));
      if (cLower) activeGroups.push(clean(SETS.lower, cSimilar, cAmbig));
      if (cNums) activeGroups.push(clean(SETS.nums, cSimilar, cAmbig));
      if (cSyms) activeGroups.push(clean(SETS.syms, cSimilar, cAmbig));

      const validGroups = activeGroups.filter(g => g.length > 0);

      if (!validGroups.length) {
        setMsg('Select at least one character type.');
        setPassword('');
        rateStrength(0, 0);
        return;
      }

      const pool = validGroups.join('');
      if (cNorepeat && currentLen > pool.length) {
        setMsg("Length is too long for 'no repeats'. Lower the length.");
        return;
      }

      const chars: string[] = [];
      // 1) guarantee at least one character from each active group
      validGroups.forEach(g => {
        chars.push(g[randInt(g.length)]);
      });

      // 2) fill remainder
      while (chars.length < currentLen) {
        let options = pool;
        if (cNorepeat) {
          options = [...pool].filter(c => !chars.includes(c)).join('');
        }
        chars.push(options[randInt(options.length)]);
      }

      const finalChars = chars.slice(0, currentLen);

      // 3) Fisher-Yates shuffle
      for (let i = finalChars.length - 1; i > 0; i--) {
        const j = randInt(i + 1);
        const temp = finalChars[i];
        finalChars[i] = finalChars[j];
        finalChars[j] = temp;
      }

      // 4) Force start with letter if requested
      if (cStart) {
        const letters = clean(SETS.upper + SETS.lower, cSimilar, cAmbig);
        const k = finalChars.findIndex(c => letters.includes(c));
        if (k > 0) {
          const temp = finalChars[0];
          finalChars[0] = finalChars[k];
          finalChars[k] = temp;
        }
      }

      const result = finalChars.join('');
      setPassword(result);
      setMsg('');
      rateStrength(result.length, pool.length);
    },
    [len, upper, lower, nums, syms, similar, ambig, norepeat, start, rateStrength]
  );

  // Initial password generation on mount
  useEffect(() => {
    generate();
  }, [generate]);

  // Real-Time Firebase Listener for Device State Synchronization
  useEffect(() => {
    if (!currentUser) return;

    const stateDocPath = `users/${currentUser.uid}/device_state/current`;
    const unsubscribe = onSnapshot(
      doc(db, 'users', currentUser.uid, 'device_state', 'current'),
      docSnap => {
        if (!docSnap.exists()) return;
        const data = docSnap.data();
        isRemoteSyncRef.current = true;

        if (typeof data.length === 'number') setLen(data.length);
        if (typeof data.preset === 'string') setPreset(data.preset);
        if (typeof data.upper === 'boolean') setUpper(data.upper);
        if (typeof data.lower === 'boolean') setLower(data.lower);
        if (typeof data.nums === 'boolean') setNums(data.nums);
        if (typeof data.syms === 'boolean') setSyms(data.syms);
        if (typeof data.similar === 'boolean') setSimilar(data.similar);
        if (typeof data.ambig === 'boolean') setAmbig(data.ambig);
        if (typeof data.norepeat === 'boolean') setNorepeat(data.norepeat);
        if (typeof data.start === 'boolean') setStart(data.start);

        setTimeout(() => {
          isRemoteSyncRef.current = false;
        }, 300);
      },
      error => {
        handleFirestoreError(error, OperationType.GET, stateDocPath);
      }
    );

    return () => unsubscribe();
  }, [currentUser]);

  // Broadcast device state changes to Firebase in real-time
  const syncDeviceState = useCallback(
    (cfg: GeneratorConfig) => {
      if (!currentUser || isRemoteSyncRef.current) return;

      if (syncTimeoutRef.current) clearTimeout(syncTimeoutRef.current);
      syncTimeoutRef.current = setTimeout(async () => {
        const statePath = `users/${currentUser.uid}/device_state/current`;
        try {
          await setDoc(
            doc(db, 'users', currentUser.uid, 'device_state', 'current'),
            {
              userId: currentUser.uid,
              length: cfg.len,
              preset: cfg.preset,
              upper: cfg.upper,
              lower: cfg.lower,
              nums: cfg.nums,
              syms: cfg.syms,
              similar: cfg.similar,
              ambig: cfg.ambig,
              norepeat: cfg.norepeat,
              start: cfg.start,
              updatedAt: serverTimestamp()
            },
            { merge: true }
          );
        } catch (err) {
          handleFirestoreError(err, OperationType.WRITE, statePath);
        }
      }, 250);
    },
    [currentUser]
  );

  // Synchronize history (Local Vault + Real-Time Firebase)
  useEffect(() => {
    if (!currentUser) {
      const local = getLocalVaultItems();
      setRawHistory(local);
      return;
    }

    const passwordsPath = `users/${currentUser.uid}/passwords`;
    const colRef = collection(db, 'users', currentUser.uid, 'passwords');

    const unsubscribe = onSnapshot(
      colRef,
      snapshot => {
        const items: RawVaultItem[] = [];
        snapshot.forEach(docSnap => {
          const d = docSnap.data();
          items.push({
            id: docSnap.id,
            name: d.name || 'Untitled',
            password: d.password,
            time: d.time || '',
            userId: d.userId,
            createdAt: d.createdAt,
            isLocal: false
          });
        });

        // Also check if any unmigrated local items exist
        const local = getLocalVaultItems();
        const merged = [...items];
        for (const loc of local) {
          if (!merged.some(m => m.id === loc.id)) {
            merged.push({ ...loc, isLocal: true });
          }
        }

        merged.sort((a, b) => {
          const tA = (typeof a.createdAt === 'object' && a.createdAt?.toMillis) ? a.createdAt.toMillis() : 0;
          const tB = (typeof b.createdAt === 'object' && b.createdAt?.toMillis) ? b.createdAt.toMillis() : 0;
          return tB - tA;
        });
        setRawHistory(merged);
      },
      error => {
        handleFirestoreError(error, OperationType.LIST, passwordsPath);
      }
    );

    return () => unsubscribe();
  }, [currentUser]);

  // When user signs in, automatically upload any offline local vault items to Firestore
  useEffect(() => {
    if (!currentUser) return;
    const local = getLocalVaultItems();
    if (local.length === 0) return;

    let active = true;
    const syncLocalToCloud = async () => {
      let count = 0;
      for (const item of local) {
        try {
          await setDoc(doc(db, 'users', currentUser.uid, 'passwords', item.id), {
            id: item.id,
            name: item.name,
            password: item.password,
            time: item.time,
            userId: currentUser.uid,
            createdAt: serverTimestamp(),
            updatedAt: serverTimestamp()
          });
          count++;
        } catch (e) {
          console.warn('Deferred syncing item to cloud:', item.id, e);
        }
      }
      if (count > 0 && active) {
        localStorage.removeItem(LOCAL_STORAGE_KEY);
        setHmsg(`Synced ${count} password${count > 1 ? 's' : ''} to your cloud vault!`);
      }
    };

    syncLocalToCloud();
    return () => {
      active = false;
    };
  }, [currentUser]);

  // Decrypt items when master password is valid
  const decryptVault = useCallback(async (masterKey: string, items: RawVaultItem[]) => {
    if (!masterKey) {
      setHmsg('Type your master password.');
      return false;
    }

    if (items.length === 0) {
      setDecryptedHistory([]);
      setHmsg('No saved passwords yet.');
      return true;
    }

    try {
      const decryptedList: DecryptedItem[] = [];
      for (const item of items) {
        const plainPw = await decryptPassword(masterKey, item.password);
        decryptedList.push({
          id: item.id,
          name: item.name,
          password: plainPw,
          time: item.time,
          isLocal: item.isLocal
        });
      }
      setDecryptedHistory(decryptedList);
      setHmsg('');
      return true;
    } catch {
      setHmsg('Wrong master password.');
      setDecryptedHistory([]);
      return false;
    }
  }, []);

  // Update decrypted list if rawHistory updates and history is revealed
  useEffect(() => {
    if (historyRevealed && masterPassword) {
      decryptVault(masterPassword, rawHistory);
    }
  }, [rawHistory, historyRevealed, masterPassword, decryptVault]);

  // Handlers
  const handlePresetChange = (newPreset: string) => {
    setPreset(newPreset);
    const p = PRESETS[newPreset];
    if (p) {
      const newLen = p.len ?? len;
      const nUpper = p.upper ?? upper;
      const nLower = p.lower ?? lower;
      const nNums = p.nums ?? nums;
      const nSyms = p.syms ?? syms;
      const nSimilar = p.similar ?? similar;
      const nAmbig = p.ambig ?? ambig;
      const nNorepeat = p.norepeat ?? norepeat;
      const nStart = p.start ?? start;

      setLen(newLen);
      setUpper(nUpper);
      setLower(nLower);
      setNums(nNums);
      setSyms(nSyms);
      setSimilar(nSimilar);
      setAmbig(nAmbig);
      setNorepeat(nNorepeat);
      setStart(nStart);

      generate(newLen, nUpper, nLower, nNums, nSyms, nSimilar, nAmbig, nNorepeat, nStart);

      syncDeviceState({
        len: newLen,
        preset: newPreset,
        upper: nUpper,
        lower: nLower,
        nums: nNums,
        syms: nSyms,
        similar: nSimilar,
        ambig: nAmbig,
        norepeat: nNorepeat,
        start: nStart
      });
    }
  };

  const handleLenChange = (newLen: number) => {
    setLen(newLen);
    generate(newLen, upper, lower, nums, syms, similar, ambig, norepeat, start);
    syncDeviceState({
      len: newLen,
      preset,
      upper,
      lower,
      nums,
      syms,
      similar,
      ambig,
      norepeat,
      start
    });
  };

  const handleOptionChange = (key: keyof GeneratorConfig, value: boolean) => {
    setPreset('custom');
    const updated = {
      len,
      preset: 'custom',
      upper: key === 'upper' ? value : upper,
      lower: key === 'lower' ? value : lower,
      nums: key === 'nums' ? value : nums,
      syms: key === 'syms' ? value : syms,
      similar: key === 'similar' ? value : similar,
      ambig: key === 'ambig' ? value : ambig,
      norepeat: key === 'norepeat' ? value : norepeat,
      start: key === 'start' ? value : start
    };

    if (key === 'upper') setUpper(value);
    if (key === 'lower') setLower(value);
    if (key === 'nums') setNums(value);
    if (key === 'syms') setSyms(value);
    if (key === 'similar') setSimilar(value);
    if (key === 'ambig') setAmbig(value);
    if (key === 'norepeat') setNorepeat(value);
    if (key === 'start') setStart(value);

    generate(
      updated.len,
      updated.upper,
      updated.lower,
      updated.nums,
      updated.syms,
      updated.similar,
      updated.ambig,
      updated.norepeat,
      updated.start
    );

    syncDeviceState(updated);
  };

  const copyToClipboard = async () => {
    if (!password) {
      setMsg('Generate a password first.');
      return;
    }
    try {
      await navigator.clipboard.writeText(password);
    } catch {
      const pwInput = document.getElementById('pw') as HTMLInputElement | null;
      if (pwInput) {
        pwInput.select();
        document.execCommand('copy');
      }
    }
    setMsg('Copied to clipboard.');
  };

  const clearPassword = () => {
    setPassword('');
    setBarWidth('0%');
    setStrengthText('Strength: –');
    setMsg('');
  };

  const handleCopyDomain = async () => {
    if (!authWarning?.domain) return;
    try {
      await navigator.clipboard.writeText(authWarning.domain);
      setCopiedDomain(true);
      setTimeout(() => setCopiedDomain(false), 2500);
    } catch {
      // fallback
    }
  };

  // Google Login / Real-Time Sync Activation
  const handleGoogleSignIn = async () => {
    try {
      setHmsg('Opening Google sign-in...');
      await signInWithPopup(auth, googleProvider);
      setAuthWarning(null);
      setHmsg('Signed in! Real-time synchronization active.');
    } catch (err: unknown) {
      const firebaseErr = err as { code?: string; message?: string };
      const code = firebaseErr?.code || '';
      const domain = typeof window !== 'undefined' ? window.location.hostname : '';

      if (code === 'auth/unauthorized-domain') {
        console.warn(`[Firebase Auth] Domain "${domain}" is not authorized in Firebase Console.`);
        setAuthWarning({
          domain: domain || (typeof window !== 'undefined' ? window.location.host : 'Current preview domain'),
          projectId: 'graphical-castle-m6rpq',
          settingsUrl: 'https://console.firebase.google.com/project/graphical-castle-m6rpq/authentication/settings'
        });
        setHmsg('Domain authorization needed in Firebase Console. Local encrypted vault remains active.');
      } else if (code === 'auth/popup-blocked') {
        console.warn('[Firebase Auth] Sign-in popup was blocked by browser.');
        setHmsg('Sign-in popup was blocked. Please allow popups for this site and try again.');
      } else if (code === 'auth/popup-closed-by-user' || code === 'auth/cancelled-popup-request') {
        console.warn('[Firebase Auth] Sign-in cancelled by user.');
        setHmsg('Sign-in cancelled.');
      } else {
        console.warn('[Firebase Auth] Sign-in error:', firebaseErr?.message || code);
        setHmsg(`Sign-in error: ${firebaseErr?.message || code || 'Authentication failed'}. Local vault active.`);
      }
    }
  };

  const handleSignOut = async () => {
    try {
      await signOut(auth);
      setAuthWarning(null);
      const local = getLocalVaultItems();
      setRawHistory(local);
      setDecryptedHistory([]);
      setHistoryRevealed(false);
      setHmsg('Signed out. Local encrypted vault active.');
    } catch (err) {
      console.warn('Sign out error:', err);
    }
  };

  // Save to History (Cloud when authenticated, Local Encrypted Vault when offline)
  const savePassword = async () => {
    if (!masterPassword) {
      setHmsg('Type your master password.');
      return;
    }
    if (!password) {
      setMsg('Generate a password first.');
      return;
    }

    try {
      setHmsg('Encrypting password...');
      const encryptedBlob = await encryptPassword(masterPassword, password);
      const entryId = crypto.randomUUID().replace(/-/g, '').slice(0, 16);
      const entryName = hname.trim() || 'Untitled';
      const formattedTime = formatCurrentTime();

      if (currentUser) {
        setHmsg('Encrypting and syncing to cloud...');
        const entryPath = `users/${currentUser.uid}/passwords/${entryId}`;
        await setDoc(doc(db, 'users', currentUser.uid, 'passwords', entryId), {
          id: entryId,
          name: entryName,
          password: encryptedBlob,
          time: formattedTime,
          userId: currentUser.uid,
          createdAt: serverTimestamp(),
          updatedAt: serverTimestamp()
        });
        setHmsg('Saved to cloud vault.');
      } else {
        const newItem: RawVaultItem = {
          id: entryId,
          name: entryName,
          password: encryptedBlob,
          time: formattedTime,
          isLocal: true
        };
        const local = [newItem, ...getLocalVaultItems().filter(i => i.id !== entryId)];
        saveLocalVaultItems(local);
        setRawHistory(local);
        setHmsg('Saved to local encrypted vault.');
      }

      setHistoryRevealed(true);
      setHname('');
    } catch (err) {
      if (currentUser) {
        setHmsg('Failed to save to cloud.');
        handleFirestoreError(err, OperationType.WRITE, `users/${currentUser.uid}/passwords`);
      } else {
        setHmsg('Failed to save to local vault.');
      }
    }
  };

  // Show History
  const showHistory = async () => {
    if (!masterPassword) {
      setHmsg('Type your master password.');
      return;
    }

    setHistoryRevealed(true);
    await decryptVault(masterPassword, rawHistory);
  };

  // Delete an entry
  const deleteEntry = async (entryId: string, isLocal?: boolean) => {
    if (isLocal || !currentUser) {
      const local = getLocalVaultItems().filter(i => i.id !== entryId);
      saveLocalVaultItems(local);
      setRawHistory(prev => prev.filter(i => i.id !== entryId));
      setDecryptedHistory(prev => prev.filter(i => i.id !== entryId));
      setHmsg('Entry removed from local vault.');
      return;
    }

    const entryPath = `users/${currentUser.uid}/passwords/${entryId}`;
    try {
      await deleteDoc(doc(db, 'users', currentUser.uid, 'passwords', entryId));
      setRawHistory(prev => prev.filter(i => i.id !== entryId));
      setDecryptedHistory(prev => prev.filter(i => i.id !== entryId));
      setHmsg('Entry removed from cloud vault.');
    } catch (err) {
      handleFirestoreError(err, OperationType.DELETE, entryPath);
    }
  };

  return (
    <main className="app">
      {/* Real-Time Sync Status Bar */}
      <div className="sync-bar">
        <div className="sync-status">
          <div className={`sync-dot ${currentUser ? '' : authWarning ? 'warning' : 'offline'}`} />
          <span>
            {authReady
              ? currentUser
                ? `Cloud Sync: Active (${currentUser.email || 'Google User'})`
                : authWarning
                ? 'Cloud Sync: Domain Setup Required'
                : 'Vault: Local Encrypted (Cloud Sync ready)'
              : 'Connecting...'}
          </span>
        </div>
        <div className="sync-actions">
          {currentUser ? (
            <button type="button" className="sync-btn" onClick={handleSignOut}>
              Sign out
            </button>
          ) : (
            <button
              type="button"
              className={`sync-btn ${authWarning ? 'highlight' : ''}`}
              onClick={handleGoogleSignIn}
            >
              Sign in with Google
            </button>
          )}
        </div>
      </div>

      {authWarning && (
        <div className="auth-alert" role="alert">
          <div className="auth-alert-header">
            <div className="auth-alert-title">
              <span className="auth-alert-badge">Action Required</span>
              <span>Firebase Domain Authorization</span>
            </div>
            <button
              type="button"
              className="auth-alert-close"
              onClick={() => setAuthWarning(null)}
              aria-label="Dismiss warning"
            >
              ✕
            </button>
          </div>
          <p className="auth-alert-desc">
            Google Sign-In requires your current preview domain to be in your Firebase authorized domains list:
          </p>
          <div className="domain-copy-box">
            <code className="domain-code">{authWarning.domain}</code>
            <button
              type="button"
              className="domain-copy-btn"
              onClick={handleCopyDomain}
            >
              {copiedDomain ? 'Copied!' : 'Copy Domain'}
            </button>
          </div>
          <div className="auth-alert-steps">
            <ol>
              <li>
                Open{' '}
                <a
                  href={authWarning.settingsUrl}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="auth-link"
                >
                  Firebase Auth Settings ↗
                </a>
              </li>
              <li>Under <strong>Authorized domains</strong>, click <strong>Add domain</strong></li>
              <li>Paste the domain and click <strong>Save</strong></li>
            </ol>
          </div>
          <div className="auth-alert-actions">
            <button
              type="button"
              className="sync-btn auth-retry-btn"
              onClick={handleGoogleSignIn}
            >
              Retry Google Sign In
            </button>
            <span className="auth-alert-local-note">
              Local Encrypted Vault is active — you can continue saving passwords right now.
            </span>
          </div>
        </div>
      )}

      <h1>Password Generator</h1>
      <p className="sub">Pick your options, then generate. Everything runs in your browser.</p>

      <div className="out">
        <input
          id="pw"
          readOnly
          aria-label="Generated password"
          placeholder="Click Generate"
          value={password}
        />
        <button id="copy" type="button" onClick={copyToClipboard}>
          Copy
        </button>
      </div>

      <div className="meter">
        <div id="bar" style={{ width: barWidth, background: barColor }} />
      </div>
      <div id="strength">{strengthText}</div>

      <div className="row">
        <span>Preset</span>
        <select
          id="preset"
          value={preset}
          onChange={e => handlePresetChange(e.target.value)}
        >
          <option value="custom">Custom</option>
          <option value="strong">Strong (20 chars, all types)</option>
          <option value="easy">Easy to read (no look-alikes)</option>
          <option value="pin">PIN (numbers only)</option>
          <option value="letters">Letters only</option>
        </select>
      </div>

      <div className="row">
        <span>Length</span>
        <strong id="lenLabel">{len}</strong>
      </div>
      <input
        type="range"
        id="len"
        min={4}
        max={64}
        value={len}
        onChange={e => handleLenChange(Number(e.target.value))}
      />

      <div className="grid">
        <label className="opt">
          <input
            type="checkbox"
            id="upper"
            checked={upper}
            onChange={e => handleOptionChange('upper', e.target.checked)}
          />{' '}
          Uppercase (A–Z)
        </label>
        <label className="opt">
          <input
            type="checkbox"
            id="lower"
            checked={lower}
            onChange={e => handleOptionChange('lower', e.target.checked)}
          />{' '}
          Lowercase (a–z)
        </label>
        <label className="opt">
          <input
            type="checkbox"
            id="nums"
            checked={nums}
            onChange={e => handleOptionChange('nums', e.target.checked)}
          />{' '}
          Numbers (0–9)
        </label>
        <label className="opt">
          <input
            type="checkbox"
            id="syms"
            checked={syms}
            onChange={e => handleOptionChange('syms', e.target.checked)}
          />{' '}
          Symbols (!@#$)
        </label>
        <label className="opt">
          <input
            type="checkbox"
            id="similar"
            checked={similar}
            onChange={e => handleOptionChange('similar', e.target.checked)}
          />{' '}
          No look-alikes (O 0 l 1 I)
        </label>
        <label className="opt">
          <input
            type="checkbox"
            id="ambig"
            checked={ambig}
            onChange={e => handleOptionChange('ambig', e.target.checked)}
          />{' '}
          No brackets/quotes
        </label>
        <label className="opt">
          <input
            type="checkbox"
            id="norepeat"
            checked={norepeat}
            onChange={e => handleOptionChange('norepeat', e.target.checked)}
          />{' '}
          No repeated characters
        </label>
        <label className="opt">
          <input
            type="checkbox"
            id="start"
            checked={start}
            onChange={e => handleOptionChange('start', e.target.checked)}
          />{' '}
          Start with a letter
        </label>
      </div>

      <div className="actions">
        <button id="gen" type="button" onClick={() => generate()}>
          Generate password
        </button>
        <button id="clear" className="ghost" type="button" onClick={clearPassword}>
          Clear
        </button>
      </div>
      <div id="msg" role="status">
        {msg}
      </div>

      <section className="hist">
        <h2>Private history</h2>
        <p className="sub" style={{ marginBottom: '4px' }}>
          Saved in an encrypted vault synchronized across all your devices in real-time with Firebase.
        </p>
        <input
          type="password"
          id="master"
          placeholder="Master password"
          autoComplete="off"
          value={masterPassword}
          onChange={e => setMasterPassword(e.target.value)}
        />
        <input
          type="text"
          id="hname"
          placeholder="Name (e.g. Gmail)"
          value={hname}
          onChange={e => setHname(e.target.value)}
        />
        <div className="actions">
          <button id="hsave" type="button" onClick={savePassword}>
            Save password
          </button>
          <button id="hshow" className="ghost" type="button" onClick={showHistory}>
            Show history
          </button>
        </div>
        <div id="hmsg" role="status">
          {hmsg}
        </div>
        <div id="hlist">
          {historyRevealed &&
            decryptedHistory.map(item => (
              <div key={item.id} className="item">
                <div className="item-content">
                  <div>
                    {item.name} · {item.time}
                    <span className={`vault-badge ${item.isLocal ? 'local' : 'cloud'}`}>
                      {item.isLocal ? 'Local' : 'Cloud'}
                    </span>
                  </div>
                  <b>{item.password}</b>
                </div>
                <div className="item-actions">
                  <button
                    type="button"
                    className="item-btn"
                    onClick={() => {
                      navigator.clipboard.writeText(item.password);
                      setHmsg(`Copied ${item.name} password.`);
                    }}
                    title="Copy"
                  >
                    Copy
                  </button>
                  <button
                    type="button"
                    className="item-btn"
                    onClick={() => deleteEntry(item.id, item.isLocal)}
                    title="Delete"
                  >
                    Delete
                  </button>
                </div>
              </div>
            ))}
        </div>
      </section>
    </main>
  );
}
