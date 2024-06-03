"use client";

import { useEffect, useState } from "react";
import { openDB } from "idb";
import { fetchAndConvertToUint8Array } from "./utils";
import { generateNullifier } from "./nullifier";

export default function Home() {
  const [isRunning, setIsRunning] = useState(false);
  const [worker, setWorker] = useState<Worker | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [selectedOption, setSelectedOption] = useState<string | null>(null);

  const initializeWorker = () => {
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
  };

  useEffect(() => {
    initializeWorker();
    return () => worker?.terminate();
  }, []);

  useEffect(() => {
    if (selectedOption) {
      initializeWorker();
      const downloadAndStoreObject = async () => {
        setIsLoading(true);
        try {
          const db = await openDB("MyDatabase", 1, {
            upgrade(db) {
              db.createObjectStore("DataStore");
            },
          });

          const vkKey =
            selectedOption === "signature" ? "vk_signature" : "vk_merkle";
          const pkKey =
            selectedOption === "signature" ? "pk_signature" : "pk_merkle";

          const storedVk = await db.get("DataStore", vkKey);
          const storedPk = await db.get("DataStore", pkKey);

          if (storedVk && storedPk) {
            console.log("Keys already stored in Indexeddb");
            setIsLoading(false);
          } else {
            console.log("Downloading and storing keys");
            const vkUrl =
              selectedOption === "signature"
                ? "https://storage.googleapis.com/plume-keys/plume_verify_vk_15.bin"
                : "https://storage.googleapis.com/plume-keys/plume_merkle_verify_vk_15_8.bin";
            const pkUrl =
              selectedOption === "signature"
                ? "https://storage.googleapis.com/plume-keys/plume_verify_pk_15.bin"
                : "https://storage.googleapis.com/plume-keys/plume_merkle_verify_pk_15_8.bin";

            const vk = await fetchAndConvertToUint8Array(vkUrl);
            const pk = await fetchAndConvertToUint8Array(pkUrl);

            await db.put("DataStore", vk, vkKey);
            await db.put("DataStore", pk, pkKey);
            setIsLoading(false);
            console.log("Keys downloaded and stored in Indexeddb");
          }
        } catch (error) {
          console.error("Error downloading and storing object:", error);
          setIsLoading(false);
        }
      };

      downloadAndStoreObject();
    }
  }, [selectedOption]);

  const runMain = async () => {
    if (worker && selectedOption) {
      setIsRunning(true);

      try {
        const db = await openDB("MyDatabase", 1);
        const vkKey =
          selectedOption === "signature" ? "vk_signature" : "vk_merkle";
        const pkKey =
          selectedOption === "signature" ? "pk_signature" : "pk_merkle";

        const storedVk = await db.get("DataStore", vkKey);
        const storedPk = await db.get("DataStore", pkKey);

        if (storedVk && storedPk) {
          const plume = await generateNullifier();
          const data = {
            provingKey: storedPk,
            verifyingKey: storedVk,
            plume,
            option: selectedOption,
          };
          worker.postMessage({ action: "runMain", data: data });
        } else {
          console.error("Keys not found in Indexeddb");
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
      <div className="max-w-lg w-full px-8 py-10 bg-white rounded-lg shadow-lg">
        <h1 className="text-4xl font-bold text-center text-gray-800 mb-8">
          PLUME Verification in WASM
        </h1>
        <div className="flex flex-col items-center">
          <div className="mb-6 flex justify-center space-x-8">
            <label
              className={`flex items-center justify-center w-48 h-24 cursor-pointer p-4 border-2 rounded-lg ${
                selectedOption === "signature"
                  ? "bg-blue-100 border-blue-500"
                  : "border-gray-300"
              }`}
            >
              <input
                type="radio"
                value="signature"
                checked={selectedOption === "signature"}
                onChange={() => setSelectedOption("signature")}
                className="form-radio h-0 w-0 opacity-0"
              />
              <span className="text-lg text-gray-800 text-center">
                Verify PLUME Signature
              </span>
            </label>
            <label
              className={`flex items-center justify-center w-48 h-24 cursor-pointer p-4 border-2 rounded-lg ${
                selectedOption === "merkle"
                  ? "bg-blue-100 border-blue-500"
                  : "border-gray-300"
              }`}
            >
              <input
                type="radio"
                value="merkle"
                checked={selectedOption === "merkle"}
                onChange={() => setSelectedOption("merkle")}
                className="form-radio h-0 w-0 opacity-0"
              />
              <span className="text-lg text-gray-800 text-center">
                Verify PLUME Signature + Merkle Proof
              </span>
            </label>
          </div>
          <div className="flex justify-center w-full">
            <button
              onClick={runMain}
              disabled={isRunning || isLoading || !selectedOption}
              className={`px-8 py-3 text-lg font-semibold rounded-full focus:outline-none focus:shadow-outline ${
                isRunning || isLoading || !selectedOption
                  ? "bg-gray-400 cursor-not-allowed"
                  : "bg-blue-600 hover:bg-blue-500 text-white"
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
          </div>
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
