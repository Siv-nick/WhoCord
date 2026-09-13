// src/App.tsx
import React from "react";
import { BrowserRouter, Route, Routes } from "react-router-dom";

// ── Canvas (new) ────────────────────────────────────────────────────────
import StartPage   from "./pages/StartPage";
import GraphCanvas from "./pages/GraphCanvas";

// ── Legacy dashboard shell (kept intact) ────────────────────────────────
import Layout            from "./components/Layout";
import Dashboard         from "./pages/Dashboard";
import InvestigationLive from "./pages/InvestigationLive";
import History           from "./pages/History";
import ReportViewer      from "./pages/ReportViewer";
import Config            from "./pages/Config";

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        {/* ── New canvas routes ──────────────────────────────────── */}
        <Route path="/"       element={<StartPage />} />
        <Route path="/canvas" element={<GraphCanvas />} />

        {/* ── Legacy dashboard preserved at /dashboard/* ─────────── */}
        <Route path="/dashboard" element={<Layout />}>
          <Route index                  element={<Dashboard />} />
          <Route path="live"            element={<InvestigationLive />} />
          <Route path="history"         element={<History />} />
          <Route path="report"          element={<ReportViewer />} />
          <Route path="report/:jobId"   element={<ReportViewer />} />
          <Route path="config"          element={<Config />} />
        </Route>
      </Routes>
    </BrowserRouter>
  );
}
