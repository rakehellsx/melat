import { Routes, Route, Navigate } from "react-router";
import Layout from "./components/Layout";
import Dashboard from "./pages/Dashboard";
import Modeling from "./pages/Modeling";
import Sessions from "./pages/Sessions";
import Ingest from "./pages/Ingest";
import Analysis from "./pages/Analysis";
import Alerts from "./pages/Alerts";
import { Toaster } from "@/components/ui/sonner";

export default function App() {
  return (
    <>
      <Routes>
        <Route element={<Layout />}>
          <Route path="/" element={<Dashboard />} />
          <Route path="/fields" element={<Modeling />} />
          <Route path="/sessions" element={<Sessions />} />
          <Route path="/ingest" element={<Ingest />} />
          <Route path="/analysis" element={<Analysis />} />
          <Route path="/alerts" element={<Alerts />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Route>
      </Routes>
      <Toaster position="top-right" theme="light" />
    </>
  );
}
