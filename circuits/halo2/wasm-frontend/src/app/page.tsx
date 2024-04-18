"use client";

import { useEffect, useState } from "react";

export default function Home() {
  const [isRunning, setIsRunning] = useState(false);
  const [worker, setWorker] = useState<Worker | null>(null);

  useEffect(() => {
    const newWorker = new Worker(new URL("./worker.ts", import.meta.url), {
      type: "module",
    });
    newWorker.onmessage = (e) => {
      if (e.data.status === "success") {
        console.log(e.data.message);
        setIsRunning(false);
      } else if (e.data.status === "error") {
        console.error(e.data.message);
        setIsRunning(false);
      }
    };
    setWorker(newWorker);

    // Cleanup function to terminate the worker when the component unmounts
    return () => newWorker.terminate();
  }, []);

  const runMain = () => {
    if (worker) {
      setIsRunning(true);
      worker.postMessage({ action: "runMain" });
    }
  };

  return (
    <header className="flex min-h-screen flex-col items-center justify-center p-24">
      <h1 className="text-4xl font-bold">Plume Verification in Wasm</h1>
      <button onClick={runMain} disabled={isRunning} className="bg-blue-500 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded">
        {isRunning ? "Running..." : "Run Main"}
      </button>
    </header>
  );
}
