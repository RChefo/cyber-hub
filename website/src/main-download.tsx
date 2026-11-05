import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import DownloadPage from "./download/Download";
import "./styles.css";

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <DownloadPage />
  </StrictMode>,
);
