/** Why a TCP forward's connect failed, carried in `ControlError.detailJson` as `reason`. A failure
 * outside these kinds carries no reason. */
export const FORWARD_CONNECT_REASONS = [
  "connection-refused",
  "name-unresolved",
  "network-unreachable",
  "dial-timeout",
] as const;

export type ForwardConnectReason = (typeof FORWARD_CONNECT_REASONS)[number];

/** Why a forward bound to a session was refused, carried in `ControlError.detailJson` as
 * `reason`. A bound forward whose session's leader exits ends with an `End` whose `error` is
 * `owner-exited`. */
export const FORWARD_BINDING_REFUSALS = [
  "owner-exited",
  "peer-mismatch",
  "binding-unverifiable",
] as const;

export type ForwardBindingRefusal = (typeof FORWARD_BINDING_REFUSALS)[number];
