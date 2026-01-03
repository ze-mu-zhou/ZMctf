import { StrictMode } from "react";
import reactDom from "react-dom/client";

import App from "./App";
import "./styles.css";

const root = document.getElementById("root");
if (!root) {
  throw new Error("缺少根节点：#root");
}

reactDom.createRoot(root).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
