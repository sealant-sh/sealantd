// The machine reasons a refused forward carries in `ControlError.detailJson` as `reason`. sealantd
// names the same strings (`sealant_protocol::reason`), and a test there keeps the lists equal.

/** Why a TCP forward's connect failed. A failure outside these kinds carries no reason. */
export const FORWARD_CONNECT_REASONS = [
  "connection-refused",
  "name-unresolved",
  "network-unreachable",
  "dial-timeout",
] as const;

export type ForwardConnectReason = (typeof FORWARD_CONNECT_REASONS)[number];
