import { describe, expect, it } from "vitest";
import { editDropsCredential, editKeepsPasswordOfOtherUser, originOf } from "./taxiiCredential";

const stored = { discoveryUrl: "https://taxii.example.org/taxii2/", auth: "basic" as const, credentialStored: true };

describe("TAXII credential warnings", () => {
  it("compares origins the way the backend does", () => {
    expect(originOf("https://TAXII.example.org:443/taxii2/")).toBe("https://taxii.example.org");
    expect(originOf("https://taxii.example.org:8443/x/")).toBe("https://taxii.example.org:8443");
    expect(originOf("not a url")).toBeNull();
  });

  it("warns only when a stored credential would be deleted", () => {
    // same origin, other path or user name: kept
    expect(editDropsCredential(stored, { discoveryUrl: "https://taxii.example.org/other/", auth: "basic" })).toBe(false);
    // another host, port or kind of authentication: deleted
    expect(editDropsCredential(stored, { discoveryUrl: "https://elsewhere.example.net/taxii2/", auth: "basic" })).toBe(true);
    expect(editDropsCredential(stored, { discoveryUrl: "https://taxii.example.org:8443/taxii2/", auth: "basic" })).toBe(true);
    expect(editDropsCredential(stored, { discoveryUrl: stored.discoveryUrl, auth: "header" })).toBe(true);
    // nothing stored, a new server, or an address still being typed: no warning
    expect(editDropsCredential({ ...stored, credentialStored: false }, { discoveryUrl: "https://elsewhere.example.net/", auth: "basic" })).toBe(false);
    expect(editDropsCredential(null, { discoveryUrl: "https://elsewhere.example.net/", auth: "basic" })).toBe(false);
    expect(editDropsCredential(stored, { discoveryUrl: "https://", auth: "basic" })).toBe(false);
  });

  it("says when a kept password was typed for another user name", () => {
    const basic = { ...stored, username: "analyst" };
    expect(editKeepsPasswordOfOtherUser(basic, { discoveryUrl: basic.discoveryUrl, auth: "basic", username: "analyst" })).toBe(false);
    expect(editKeepsPasswordOfOtherUser(basic, { discoveryUrl: basic.discoveryUrl, auth: "basic", username: "other-analyst" })).toBe(true);
    // moving the server deletes the password anyway: that warning is enough
    expect(editKeepsPasswordOfOtherUser(basic, { discoveryUrl: "https://elsewhere.example.net/", auth: "basic", username: "other-analyst" })).toBe(false);
    expect(editKeepsPasswordOfOtherUser({ ...basic, credentialStored: false }, { discoveryUrl: basic.discoveryUrl, auth: "basic", username: "other-analyst" })).toBe(false);
  });
});
