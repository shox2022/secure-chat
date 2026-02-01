import { WebSocketServer } from "ws";
import crypto from "crypto";

console.log("Server starting...");

const wss = new WebSocketServer({ port: 8080 });
console.log("Server running on ws://localhost:8080");

// Store connected users with their WebSocket connections and usernames
const users = new Map();

// Function to broadcast to all users
function broadcast(message, excludeUserId = null) {
  users.forEach((userData, userId) => {
    if (userId !== excludeUserId && userData.connected) {
      userData.ws.send(JSON.stringify(message));
    }
  });
}

// Function to get user list
function getUserList() {
  return Array.from(users.values())
    .filter(user => user.connected)
    .map(user => ({
      id: user.id,
      username: user.username,
      color: user.color
    }));
}

wss.on("connection", ws => {
  const userId = crypto.randomBytes(16).toString('hex');
  console.log(`Client connected: ${userId}`);

  // Generate server ECDH key pair for this client
  const ecdh = crypto.createECDH("prime256v1");
  ecdh.generateKeys();

  // Store user with temporary data
  users.set(userId, {
    ws,
    id: userId,
    username: null, // Will be set when user provides it
    color: `#${crypto.randomBytes(3).toString('hex')}`, // Random color
    connected: true,
    ecdh,
    aesKey: null
  });

  // Send server public key to client
  ws.send(JSON.stringify({
    type: "server-public-key",
    key: ecdh.getPublicKey("base64")
  }));

  // Send current user list to the new client
  ws.send(JSON.stringify({
    type: "user-list",
    users: getUserList()
  }));

  // Notify others about new connection (after username is set)
  let userJoinedSent = false;

  ws.on("message", msg => {
    try {
      const data = JSON.parse(msg.toString());
      const userData = users.get(userId);

      // Handle key exchange
      if (data.type === "client-public-key") {
        const clientPub = Buffer.from(data.key, "base64");
        const sharedSecret = userData.ecdh.computeSecret(clientPub);

        const aesKey = crypto
          .createHash("sha256")
          .update(sharedSecret)
          .digest();

        userData.aesKey = aesKey;
        console.log(`AES key established for user: ${userId}`);

        return;
      }

      // Handle username setting
      if (data.type === "set-username") {
        if (userData.username === null) {
          userData.username = data.username || `User${Math.floor(Math.random() * 1000)}`;
          
          // Broadcast user joined
          broadcast({
            type: "user-joined",
            user: {
              id: userId,
              username: userData.username,
              color: userData.color
            }
          }, userId);

          userJoinedSent = true;
        }
        return;
      }

      // Handle chat messages
      if (data.type === "chat") {
        if (!userData.aesKey) {
          console.warn("Chat message received before AES key ready");
          return;
        }

        if (!data.iv || !data.data) {
          console.warn("Malformed chat message:", data);
          return;
        }

        // Decrypt the message
        try {
          const iv = Buffer.from(data.iv, "base64");
          const encrypted = Buffer.from(data.data, "base64");
          const tag = encrypted.subarray(encrypted.length - 16);
          const ciphertext = encrypted.subarray(0, encrypted.length - 16);

          const decipher = crypto.createDecipheriv(
            "aes-256-gcm",
            userData.aesKey,
            iv,
            { authTagLength: 16 }
          );

          decipher.setAuthTag(tag);

          const plaintext = Buffer.concat([
            decipher.update(ciphertext),
            decipher.final()
          ]).toString();

          console.log(`[${userData.username}]: ${plaintext}`);

          // Broadcast decrypted message to all users
          broadcast({
            type: "chat-message",
            sender: {
              id: userId,
              username: userData.username,
              color: userData.color
            },
            message: plaintext,
            timestamp: new Date().toISOString()
          }, userId);

        } catch (err) {
          console.error("Decryption failed:", err.message);
        }
        return;
      }

      // Handle typing indicator
      if (data.type === "typing") {
        broadcast({
          type: "user-typing",
          userId: userId,
          username: userData.username,
          isTyping: data.isTyping
        }, userId);
        return;
      }

    } catch (err) {
      console.error("Error processing message:", err);
    }
  });

  // Handle disconnection
  ws.on("close", () => {
    const userData = users.get(userId);
    if (userData) {
      userData.connected = false;
      console.log(`Client disconnected: ${userId} (${userData.username})`);
      
      // Notify others
      if (userData.username) {
        broadcast({
          type: "user-left",
          userId: userId,
          username: userData.username
        });
      }
    }
  });

  // Handle errors
  ws.on("error", (error) => {
    console.error(`WebSocket error for user ${userId}:`, error);
  });
});