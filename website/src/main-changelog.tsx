import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import ChangelogPage from "./changelog/Changelog";
import "./styles.css";

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <ChangelogPage />
  </StrictMode>,
);
