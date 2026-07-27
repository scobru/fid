# FID Client-Server Example

This directory demonstrates a client-server interaction using FID protocol for federated identity.

## Server-Side
- Handles challenge generation and passport issuing
- Communicates with clients via WebSocket or REST

## Client-Side
- Signs challenges with Zen SEA key
- Retrieves SSO tokens
- Manages deterministic identity

## Structure
```
examples/
├── server-example.js
├── client-example.ts
└── README.md
```