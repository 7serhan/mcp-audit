import { describe, it, expect } from "vitest";
import {
  isPrivateIp,
  isPrivateHost,
  isMetadataEndpoint,
} from "../../../src/utils/network.js";

describe("isPrivateIp", () => {
  it("detects loopback", () => {
    expect(isPrivateIp("127.0.0.1")).toBe(true);
    expect(isPrivateIp("127.255.255.255")).toBe(true);
  });

  it("detects class A private", () => {
    expect(isPrivateIp("10.0.0.1")).toBe(true);
    expect(isPrivateIp("10.255.255.255")).toBe(true);
  });

  it("detects class B private", () => {
    expect(isPrivateIp("172.16.0.1")).toBe(true);
    expect(isPrivateIp("172.31.255.255")).toBe(true);
  });

  it("detects class C private", () => {
    expect(isPrivateIp("192.168.0.1")).toBe(true);
    expect(isPrivateIp("192.168.255.255")).toBe(true);
  });

  it("rejects public IPs", () => {
    expect(isPrivateIp("8.8.8.8")).toBe(false);
    expect(isPrivateIp("1.1.1.1")).toBe(false);
  });
});

describe("isPrivateHost", () => {
  it("detects localhost", () => {
    expect(isPrivateHost("localhost")).toBe(true);
  });

  it("detects metadata hostnames", () => {
    expect(isPrivateHost("metadata.google.internal")).toBe(true);
  });

  it("detects IPv6 loopback", () => {
    expect(isPrivateHost("::1")).toBe(true);
  });

  it("rejects public hosts", () => {
    expect(isPrivateHost("google.com")).toBe(false);
  });
});

describe("isMetadataEndpoint", () => {
  it("detects AWS metadata", () => {
    expect(isMetadataEndpoint("http://169.254.169.254/latest/meta-data/")).toBe(true);
  });

  it("detects GCP metadata", () => {
    expect(isMetadataEndpoint("http://metadata.google.internal/computeMetadata/v1/")).toBe(true);
  });

  it("rejects normal URLs", () => {
    expect(isMetadataEndpoint("https://example.com")).toBe(false);
  });
});
