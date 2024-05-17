"use client";

import { useEffect, useState } from "react";
import { openDB } from "idb";
import { fetchAndConvertToUint8Array } from "./utils";
import { generateNullifier } from "./nullifier";

export default function Home() {
  const [isRunning, setIsRunning] = useState(false);
  const [worker, setWorker] = useState<Worker | null>(null);
  const [isLoading, setIsLoading] = useState(true);

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

    return () => newWorker.terminate();
  }, []);

  useEffect(() => {
    const downloadAndStoreObject = async () => {
      try {
        const db = await openDB("MyDatabase", 1, {
          upgrade(db) {
            db.createObjectStore("DataStore");
          },
        });

        const storedVk = await db.get("DataStore", "vk");
        const storedPk = await db.get("DataStore", "pk");

        if (storedVk && storedPk) {
          console.log(
            "Verifying key and proving key already stored in Indexeddb",
          );
          setIsLoading(false);
        } else {
          console.log("Downloading and storing verifying key and proving key");
          const vk = await fetchAndConvertToUint8Array(
            "https://storage.googleapis.com/plume-keys/plume_verify_vk_15.bin",
          );
          const pk = await fetchAndConvertToUint8Array(
            "https://storage.googleapis.com/plume-keys/plume_verify_pk_15.bin",
          );

          await db.put("DataStore", vk, "vk");
          await db.put("DataStore", pk, "pk");
          setIsLoading(false);
          console.log(
            "Verifying key and proving key downloaded and stored in Indexeddb",
          );
        }
      } catch (error) {
        console.error("Error downloading and storing object:", error);
        setIsLoading(false);
      }
    };

    downloadAndStoreObject();
  }, []);

  const runMain = async () => {
    if (worker) {
      setIsRunning(true);

      try {
        const db = await openDB("MyDatabase", 1);
        const storedVk = await db.get("DataStore", "vk");
        const storedPk = await db.get("DataStore", "pk");

        if (storedVk && storedPk) {
          const plume = await generateNullifier();
          const data = {
            provingKey: storedPk,
            verifyingKey: storedVk,
            plume,
          };
          worker.postMessage({ action: "runMain", data: data });
        } else {
          console.error("Verifying key and proving key not found in Indexeddb");
          setIsRunning(false);
        }
      } catch (error) {
        console.error("Error retrieving data from Indexeddb:", error);
        setIsRunning(false);
      }
    }
  };

  return (
    <div className="min-h-screen bg-gray-900 flex items-center justify-center">
      <div className="max-w-lg w-full px-6 py-8 bg-white rounded-lg shadow-lg">
        <h1 className="text-4xl font-bold text-center text-gray-800 mb-8">
          PLUME Verification in WASM
        </h1>
        <div className="flex flex-col items-center">
          <button
            onClick={runMain}
            disabled={isRunning || isLoading}
            className={`px-8 py-3 text-lg font-semibold rounded-full focus:outline-none focus:shadow-outline ${
              isRunning || isLoading
                ? "bg-gray-400 cursor-not-allowed"
                : "bg-gray-800 hover:bg-gray-700 text-white"
            }`}
          >
            {isRunning ? (
              <span className="flex items-center">
                <svg
                  className="animate-spin -ml-1 mr-3 h-5 w-5 text-white"
                  xmlns="http://www.w3.org/2000/svg"
                  fill="none"
                  viewBox="0 0 24 24"
                >
                  <circle
                    className="opacity-25"
                    cx="12"
                    cy="12"
                    r="10"
                    stroke="currentColor"
                    strokeWidth="4"
                  ></circle>
                  <path
                    className="opacity-75"
                    fill="currentColor"
                    d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
                  ></path>
                </svg>
                Generating...
              </span>
            ) : (
              "Generate Nullifier and Proof"
            )}
          </button>
          {isLoading && (
            <p className="mt-4 text-gray-600">
              Downloading proving and verifying keys...
            </p>
          )}
        </div>
      </div>
    </div>
  );
}
