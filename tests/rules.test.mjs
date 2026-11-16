// Checks the security rules against the local Firebase emulators (nothing touches the real project).
// Run from the repo root:  npx firebase-tools emulators:exec --only firestore,storage "node tests/rules.test.mjs"
import { readFileSync } from "node:fs";
import assert from "node:assert/strict";
import { initializeTestEnvironment, assertFails, assertSucceeds } from "@firebase/rules-unit-testing";
import { doc, getDoc, setDoc, deleteDoc, addDoc, collection, getDocs, serverTimestamp } from "firebase/firestore";
import { ref, uploadString, getBytes } from "firebase/storage";

const env = await initializeTestEnvironment({
  projectId: "demo-case-tool",
  firestore: { rules: readFileSync("firestore.rules", "utf8") },
  storage: { rules: readFileSync("storage.rules", "utf8") },
});
await env.withSecurityRulesDisabled(async (ctx) => {
  await setDoc(doc(ctx.firestore(), "allowed/ok@example.com"), { note: "approved" });
  await setDoc(doc(ctx.firestore(), "logins/old"), { email: "ok@example.com" });
  await uploadString(ref(ctx.storage(), "x.txt"), "secret");
});

const pw = (email) => ({ email, firebase: { sign_in_provider: "password" } });
const anon = env.unauthenticatedContext().firestore();
const approved = env.authenticatedContext("u1", pw("OK@example.com")).firestore();
const stranger = env.authenticatedContext("u2", pw("stranger@example.com")).firestore();
const google = env.authenticatedContext("u3", { email: "ok@example.com", firebase: { sign_in_provider: "google.com" } }).firestore();
const anonymousAuth = env.authenticatedContext("u4", { firebase: { sign_in_provider: "anonymous" } }).firestore();
const login = (email) => ({ email, name: "", at: serverTimestamp(), device: "מחשב" });

let n = 0;
async function check(name, p) { await p; n++; console.log("ok -", name); }

// not signed in: nothing
await check("signed out: cannot read allowlist", assertFails(getDoc(doc(anon, "allowed/ok@example.com"))));
await check("signed out: cannot list allowlist", assertFails(getDocs(collection(anon, "allowed"))));
await check("signed out: cannot add self to allowlist", assertFails(setDoc(doc(anon, "allowed/me@example.com"), {})));
await check("signed out: cannot write log", assertFails(addDoc(collection(anon, "logins"), login("ok@example.com"))));
await check("signed out: cannot read log", assertFails(getDocs(collection(anon, "logins"))));
await check("signed out: cannot write other collections", assertFails(setDoc(doc(anon, "cases/1"), { a: 1 })));

// signed in but not approved: nothing except learning that they are not approved
await check("stranger: own allowlist check returns 'not there'", assertSucceeds(getDoc(doc(stranger, "allowed/stranger@example.com"))));
await check("stranger: cannot read someone else's entry", assertFails(getDoc(doc(stranger, "allowed/ok@example.com"))));
await check("stranger: cannot list allowlist", assertFails(getDocs(collection(stranger, "allowed"))));
await check("stranger: cannot add self to allowlist", assertFails(setDoc(doc(stranger, "allowed/stranger@example.com"), {})));
await check("stranger: cannot write log", assertFails(addDoc(collection(stranger, "logins"), login("stranger@example.com"))));
await check("stranger: cannot read log", assertFails(getDoc(doc(stranger, "logins/old"))));
await check("stranger: cannot write other collections", assertFails(setDoc(doc(stranger, "cases/1"), { a: 1 })));

// approved email, but signed in with Google or anonymously: refused
await check("google session: cannot read allowlist", assertFails(getDoc(doc(google, "allowed/ok@example.com"))));
await check("google session: cannot write log", assertFails(addDoc(collection(google, "logins"), login("ok@example.com"))));
await check("anonymous session: refused", assertFails(getDoc(doc(anonymousAuth, "allowed/ok@example.com"))));

// approved user: only what the app needs
const mine = await getDoc(doc(approved, "allowed/ok@example.com"));
assert.equal(mine.exists(), true); n++; console.log("ok - approved: own allowlist entry is found");
await check("approved: can log own entry", assertSucceeds(addDoc(collection(approved, "logins"), login("ok@example.com"))));
await check("approved: cannot log as someone else", assertFails(addDoc(collection(approved, "logins"), login("other@example.com"))));
await check("approved: cannot add extra fields to log", assertFails(addDoc(collection(approved, "logins"), { ...login("ok@example.com"), x: 1 })));
await check("approved: cannot read log", assertFails(getDoc(doc(approved, "logins/old"))));
await check("approved: cannot change allowlist", assertFails(setDoc(doc(approved, "allowed/friend@example.com"), {})));
await check("approved: cannot remove from allowlist", assertFails(deleteDoc(doc(approved, "allowed/ok@example.com"))));
await check("approved: cannot list allowlist", assertFails(getDocs(collection(approved, "allowed"))));
await check("approved: cannot write other collections", assertFails(setDoc(doc(approved, "cases/1"), { a: 1 })));

// storage: closed to everyone
const sAnon = env.unauthenticatedContext().storage(), sOk = env.authenticatedContext("u1", pw("ok@example.com")).storage();
await check("storage: signed out cannot read", assertFails(getBytes(ref(sAnon, "x.txt"))));
await check("storage: signed out cannot upload", assertFails(uploadString(ref(sAnon, "y.txt"), "a")));
await check("storage: approved cannot read", assertFails(getBytes(ref(sOk, "x.txt"))));
await check("storage: approved cannot upload", assertFails(uploadString(ref(sOk, "y.txt"), "a")));

await env.cleanup();
console.log(`\nall ${n} checks passed`);
