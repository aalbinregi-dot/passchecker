# Cyber Security 101 · Password Security Testing Toolkit

A complete, modern, educational cybersecurity testing toolkit running 100% locally in your browser memory with zero network dependencies.

## 📂 Project Structure

- **`index.html`**: Main application entry point with sidebar navigation, SPA routing, and responsive dashboard viewports.
- **`style.css`**: Comprehensive design system featuring dark/light themes, cyber aesthetic, responsive grid, and terminal components.
- **`app.js`**: Complete client-side cryptographic engine, hash generators, pre-image crackers, password strength analyzer, and attack simulator.

## 🛠️ Included Modules

1. **Dashboard** (`#dashboard`): System overview, active dictionary metrics, and real-time session audit log.
2. **Salt to Hash Lab** (`#salt-hash`): Cryptographically secure random salting demonstration with a side-by-side **Two Users, Same Password, Different Salts** visual comparison.
3. **Password Strength Checker** (`#strength-checker`): Entropy gauge, credential hygiene, identity token leak inspection, rules checklist, and time-to-crack estimates.
4. **Dictionary Attack Simulator** (`#dict-simulator`): Load custom `.txt` wordlists, test candidates against plaintext/MD5/SHA-1/SHA-256 targets, live telemetry (attempts, speed, progress), and cyber terminal log.
5. **Hash Generator** (`#hash-generator`): Real-time digest generation for MD5, SHA-1, SHA-256, and SHA-512 with optional salting and uppercase/lowercase toggles.
6. **Hash Checker** (`#hash-checker`): Format detection, security assessment, in-memory pre-image dictionary lookup, and attack simulator bridge.
7. **Security Knowledge Base** (`#security-info`): Educational guides on hashing vs encryption vs encoding, fast vs slow KDFs, salting vs peppering, and NIST/OWASP storage standards.

## 🚀 Running Locally

Open `index.html` directly in any modern web browser, or serve it using any local HTTP server:

```bash
# Using Python 3
python3 -m http.server 3000
```

Then visit: [http://localhost:3000/index.html](http://localhost:3000/index.html)
