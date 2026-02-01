import { WebSocketServer } from "ws";
import crypto from "crypto";

console.log("Server starting...");

const wss = new WebSocketServer({ port: 8080 });
console.log("Server running on ws://localhost:8080");

wss.on("connection", ws => {
  console.log("Client connected");

  const ecdh = crypto.createECDH("prime256v1");
  ecdh.generateKeys();
  console.log("Server ECDH keys generated");

  ws.send(JSON.stringify({
    type: "server-public-key",
    key: ecdh.getPublicKey("base64")
  }));

  let aesKey;

  ws.on("message", msg => {
    const data = JSON.parse(msg.toString());

    if (data.type === "client-public-key") {
      const clientPub = Buffer.from(data.key, "base64");
      const sharedSecret = ecdh.computeSecret(clientPub);

      aesKey = crypto
        .createHash("sha256")
        .update(sharedSecret)
        .digest();

      console.log("Shared AES key established (server):", aesKey.toString("hex"));
      return;
    }

    if (data.type !== "chat") {
      return;
    }

    if (!aesKey) {
      console.warn("Chat message received before AES key ready");
      return;
    }

    if (!data.iv || !data.data) {
      console.warn("Malformed chat message:", data);
      return;
    }

    try {
      const iv = Buffer.from(data.iv, "base64");
      const encrypted = Buffer.from(data.data, "base64");

      // Web Crypto includes tag at the end (last 16 bytes)
      const tag = encrypted.subarray(encrypted.length - 16);
      const ciphertext = encrypted.subarray(0, encrypted.length - 16);

      // Create decipher with authTagLength specified
      const decipher = crypto.createDecipheriv(
        "aes-256-gcm",
        aesKey,
        iv,
        { authTagLength: 16 } // Explicitly set tag length
      );

      decipher.setAuthTag(tag);

      const plaintext = Buffer.concat([
        decipher.update(ciphertext),
        decipher.final()
      ]);

      console.log("Decrypted message:", plaintext.toString());
    } catch (err) {
      console.error("Decryption failed:", err.message);
    }
  });
});