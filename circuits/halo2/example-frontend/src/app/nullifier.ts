export interface NullifierData {
  nullifier: string;
  s: string;
  c: string;
  message: string;
  publicKey: string;
}

export async function generateNullifier(): Promise<NullifierData> {
  await window.ethereum.request({
    method: "eth_requestAccounts",
    params: [],
  });

  let accountAddress = (
    await window.ethereum.request({
      method: "eth_accounts",
      params: [],
    })
  )[0];

  let message = "CLAIM MY MONIII";

  let nullifier = await window.ethereum.request({
    method: "eth_getPlumeSignature",
    params: [message, accountAddress],
  });

  return {
    nullifier: nullifier.plume,
    s: nullifier.s,
    c: nullifier.c,
    message,
    publicKey: nullifier.publicKey,
  };
}
