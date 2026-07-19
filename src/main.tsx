import ReactDOM from "react-dom/client";
import App from "./App";
import "./styles.css";

const root = document.getElementById("root");
if (!root) throw new Error("Root element #root not found");

// StrictMode is intentionally omitted: it double-invokes effects in dev, which
// would spin up (and tear down) a second WebGL context on every mount.
ReactDOM.createRoot(root).render(<App />);
