// server.js
import { WebSocketServer } from "ws";
import crypto from "crypto";

console.log("Server starting...");

// WebSocket server on port 8080
const wss = new WebSocketServer({ port: 8080 });
console.log("Server running on ws://localhost:8080");

wss.on("connection", ws => {
  console.log("Client connected");

  // 1️⃣ Generate server ECDH key pair
  const ecdh = crypto.createECDH("prime256v1");
  ecdh.generateKeys();
  console.log("Server ECDH keys generated");

  // 2️⃣ Send server public key to client
  ws.send(JSON.stringify({
    type: "server-public-key",
    key: ecdh.getPublicKey("base64")
  }));

  let aesKey; // AES key derived from shared secret

  ws.on("message", async msg => {
    const data = JSON.parse(msg);

    // 3️⃣ Receive client public key and compute shared secret
    if (data.type === "client-public-key") {
      const clientPub = Buffer.from(data.key, "base64");
      const sharedSecret = ecdh.computeSecret(clientPub);

      // Derive AES key from shared secret (SHA-256)
      aesKey = crypto.createHash("sha256")
                     .update(sharedSecret)
                     .digest();
      console.log("Shared AES key established (server):", aesKey.toString("hex"));
    }

    // 4️⃣ Receive encrypted chat messages
    if (data.type === "chat") {
      if (!aesKey) {
        console.log("AES key not established yet");
        return;
      }

      const iv = Buffer.from(data.iv, "base64");
      const ciphertext = Buffer.from(data.data, "base64");
      const tag = Buffer.from(data.tag, "base64");

      try {
        const decipher = crypto.createDecipheriv("aes-256-gcm", aesKey, iv);
        decipher.setAuthTag(tag);

        const plaintext = Buffer.concat([
          decipher.update(ciphertext),
          decipher.final()
        ]);

        console.log("Decrypted message:", plaintext.toString());

        // Echo back decrypted message
        ws.send(JSON.stringify({ type: "chat", text: plaintext.toString() }));
      } catch (err) {
        console.log("Decryption failed:", err.message);
      }
    }
  });
});
