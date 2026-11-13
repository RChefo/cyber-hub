// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from "vitest";
import { editDropsCollections, editDropsCredential, editKeepsPasswordOfOtherUser, originOf } from "./taxiiCredential";

const stored = { discoveryUrl: "https://taxii.example.org/taxii2/", auth: "basic" as const, headerName: "", credentialStored: true };

describe("TAXII credential warnings", () => {
  it("compares origins the way the backend does", () => {
    expect(originOf("https://TAXII.example.org:443/taxii2/")).toBe("https://taxii.example.org");
    expect(originOf("https://taxii.example.org:8443/x/")).toBe("https://taxii.example.org:8443");
    expect(originOf("not a url")).toBeNull();
  });

  it("warns only when a stored credential would be deleted", () => {
    // same origin, other path or user name: kept
    expect(editDropsCredential(stored, { discoveryUrl: "https://taxii.example.org/other/", auth: "basic", headerName: "" })).toBe(false);
    // another host, port or kind of authentication: deleted
    expect(editDropsCredential(stored, { discoveryUrl: "https://elsewhere.example.net/taxii2/", auth: "basic", headerName: "" })).toBe(true);
    expect(editDropsCredential(stored, { discoveryUrl: "https://taxii.example.org:8443/taxii2/", auth: "basic", headerName: "" })).toBe(true);
    expect(editDropsCredential(stored, { discoveryUrl: stored.discoveryUrl, auth: "header", headerName: "X-Api-Key" })).toBe(true);
    // nothing stored, a new server, or an address still being typed: no warning
    expect(editDropsCredential({ ...stored, credentialStored: false }, { discoveryUrl: "https://elsewhere.example.net/", auth: "basic", headerName: "" })).toBe(false);
    expect(editDropsCredential(null, { discoveryUrl: "https://elsewhere.example.net/", auth: "basic", headerName: "" })).toBe(false);
    expect(editDropsCredential(stored, { discoveryUrl: "https://", auth: "basic", headerName: "" })).toBe(false);
  });

  it("binds an API key to its header (Mission 7)", () => {
    const key = { ...stored, auth: "header" as const, headerName: "X-Api-Key" };
    expect(editDropsCredential(key, { discoveryUrl: key.discoveryUrl, auth: "header", headerName: "x-api-key " })).toBe(false);
    expect(editDropsCredential(key, { discoveryUrl: key.discoveryUrl, auth: "header", headerName: "User-Agent" })).toBe(true);
  });

  it("says when the collections of the old origin are removed (Mission 7)", () => {
    const listed = { discoveryUrl: stored.discoveryUrl, collections: [{ id: 1 }] as never[] };
    expect(editDropsCollections(listed, { discoveryUrl: "https://taxii.example.org/other/taxii2/" })).toBe(false);
    expect(editDropsCollections(listed, { discoveryUrl: "https://elsewhere.example.net/taxii2/" })).toBe(true);
    expect(editDropsCollections({ ...listed, collections: [] }, { discoveryUrl: "https://elsewhere.example.net/taxii2/" })).toBe(false);
    expect(editDropsCollections(listed, { discoveryUrl: "https://" })).toBe(false);
    expect(editDropsCollections(null, { discoveryUrl: "https://elsewhere.example.net/taxii2/" })).toBe(false);
  });

  it("says when a kept password was typed for another user name", () => {
    const basic = { ...stored, username: "analyst" };
    expect(editKeepsPasswordOfOtherUser(basic, { discoveryUrl: basic.discoveryUrl, auth: "basic", headerName: "", username: "analyst" })).toBe(false);
    expect(editKeepsPasswordOfOtherUser(basic, { discoveryUrl: basic.discoveryUrl, auth: "basic", headerName: "", username: "other-analyst" })).toBe(true);
    // moving the server deletes the password anyway: that warning is enough
    expect(editKeepsPasswordOfOtherUser(basic, { discoveryUrl: "https://elsewhere.example.net/", auth: "basic", headerName: "", username: "other-analyst" })).toBe(false);
    expect(editKeepsPasswordOfOtherUser({ ...basic, credentialStored: false }, { discoveryUrl: basic.discoveryUrl, auth: "basic", headerName: "", username: "other-analyst" })).toBe(false);
  });
});
