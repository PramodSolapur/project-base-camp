import dotenv from "dotenv";
dotenv.config({
  path: "./.env",
});
import app from "./app.js";

const port = process.env.PORT || 5000;

const startServer = () => {
  const server = app.listen(port, () => {
    console.log(`Server is listening on http://localhost:${port}`);
  });

  // Error Handlers
  server.on("error", (err) => {
    console.error("❌ Server Error:", err.message); // Example: Port already in use
    process.exit(1);
  });

  // Unhandled synchronous code errors
  process.on("uncaughtException", (err) => {
    console.error("💥 Uncaught Exception:", err); // Example: Throwing an error in a route (throw new Error("Synchronous crash occurred!"))
    process.exit(1);
  });

  // Unhandled async promise rejections
  process.on("unhandledRejection", (reason) => {
    console.error("🚨 Unhandled Rejection:", reason); // Example: Rejecting a Promise without .catch()
    process.exit(1);
  });
};

startServer();
