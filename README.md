# 🔐 Simple Password Generator

## 📌 Problem Statement

Creating strong passwords manually can be difficult and users may reuse simple passwords.
The goal of this project is to create a **simple password generator** that generates a random password based on the length entered by the user.

The password can contain:

* Uppercase letters (`A-Z`)
* Lowercase letters (`a-z`)
* Numbers (`0-9`)
* Special characters (`!@#$%^&*-_=+?`)

---

## 💡 How Did We Solve It?

We created a Python program that:

1. Takes the required password length from the user.
2. Checks whether the length is between **4 and 128**.
3. Creates a collection of uppercase letters, lowercase letters, numbers, and symbols.
4. Combines all the characters.
5. Randomly selects characters one by one.
6. Repeats the process until the required length is reached.
7. Displays the generated password.

### Basic Algorithm

```text
START
   ↓
Take password length
   ↓
Check length (4–128)
   ↓
Create character set
   ↓
Select random character
   ↓
Add character to password
   ↓
Repeat until required length
   ↓
Display password
   ↓
END
```

---

## 🧠 Why Did We Choose This Algorithm?

We used **iteration (loop) and random selection** because the problem requires generating one character at a time until the required password length is reached.

A simple loop is sufficient because:

* The password length is limited to **4–128**.
* Each character can be selected independently.
* There is no need for sorting, searching, graphs, or complex optimization techniques.
* The approach is simple and easy to understand.

---

## ⏱️ Complexity Analysis

Let `n` be the required password length.

### Time Complexity

```text
Best Case    : O(n)
Average Case : O(n)
Worst Case   : O(n)
```

The program generates exactly `n` characters, so the loop runs `n` times.

### Space Complexity

```text
O(n)
```

The generated password contains `n` characters, so the required storage grows with the password length.

---

## ▶️ How to Execute

### Requirements

* Python 3.x
* No external libraries are required.

The program uses Python's built-in:

```python
import random
import string
```

### Steps

**1. Clone the repository**

```bash
git clone <your-github-repository-link>
```

**2. Open the project folder**

```bash
cd password-generator
```

**3. Run the Python file**

```bash
python password_generator.py
```

**4. Enter the password length**

Example:

```text
Enter password length (4-128): 12
```

**5. The program generates the password**

Example:

```text
Generated Password:

A7@kP2!xQ9#m
```

---

## 🧪 Testing

The program was tested with:

| Test Case      | Input | Expected Result        |
| -------------- | ----: | ---------------------- |
| Minimum length |   `4` | 4-character password   |
| Normal length  |  `12` | 12-character password  |
| Maximum length | `128` | 128-character password |
| Below minimum  |   `3` | Error message          |
| Above maximum  | `129` | Error message          |
| Negative value |  `-5` | Error message          |
| Text input     | `abc` | Invalid input message  |

---

## 📁 Project Structure

```text
password-generator/
│
├── password_generator.py
└── README.md
```

---

## 🎯 Key Features

* Random password generation
* Uppercase letters
* Lowercase letters
* Numbers
* Special characters
* Password length validation
* Simple and beginner-friendly implementation
* `O(n)` time complexity

---

## 👨‍💻 Project Summary

This project demonstrates how a simple **iterative algorithm with random character selection** can be used to generate passwords efficiently. The project also demonstrates basic input validation, algorithm design, complexity analysis, and testing.
