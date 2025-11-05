const functions = require('firebase-functions');
const admin = require('firebase-admin');
const crypto = require('crypto');

admin.initializeApp();
const db = admin.firestore();

// Setzen via CLI: firebase functions:config:set vouchers.secret="dein-super-secret"
const SECRET = functions.config().vouchers.secret;
const CONFIG_YEAR = 2025;

function base32ish(buf){
  return Buffer.from(buf).toString('base64').replace(/=+/g,'').replace(/\+/g,'A').replace(/\//g,'B');
}
function signPayload(uid, year, day, type, nonce){
  const payload = `${uid}|${year}|${day}|${type}|${nonce}`;
  const sig = crypto.createHmac('sha256', SECRET).update(payload).digest();
  const token = base32ish(sig).slice(0, 12);
  return { payload, token };
}
async function createVoucherDoc({uid, day, type, code, token, nonce}){
  const ref = db.collection('adv_vouchers').doc(code);
  await ref.set({
    uid, day, type, token, nonce,
    year: CONFIG_YEAR,
    createdAt: admin.firestore.FieldValue.serverTimestamp(),
    redeemed: false,
    redeemedAt: null
  }, { merge: true });
  return ref;
}

exports.signVoucher = functions.https.onCall(async (data, context) => {
  if(!context.auth) throw new functions.https.HttpsError('unauthenticated', 'Login erforderlich');
  const { day, type, nonce } = data || {};
  if(!day || !type || !nonce) throw new functions.https.HttpsError('invalid-argument', 'day; type; nonce nötig');

  const uid = context.auth.uid;
  const { token } = signPayload(uid, CONFIG_YEAR, day, type, nonce);
  const code = `${type.toUpperCase().slice(0,1)}-${String(day).padStart(2,'0')}-${token}`;
  await createVoucherDoc({ uid, day, type, code, token, nonce });
  return { code, token };
});

exports.verifyVoucher = functions.https.onCall(async (data, context) => {
  if(!context.auth) throw new functions.https.HttpsError('unauthenticated', 'Login erforderlich');
  const adminDoc = await db.collection('adv_admins').doc(context.auth.uid).get();
  if(!adminDoc.exists) throw new functions.https.HttpsError('permission-denied', 'Nur Admin');

  const { code } = data || {};
  if(!code) throw new functions.https.HttpsError('invalid-argument', 'code fehlt');

  const vref = db.collection('adv_vouchers').doc(code);
  const vsnap = await vref.get();
  if(!vsnap.exists) return { ok:false, reason:'not-found' };

  const v = vsnap.data();
  const { token } = signPayload(v.uid, v.year, v.day, v.type, v.nonce);
  const valid = token === v.token;
  return { ok: valid, redeemed: !!v.redeemed, uid: v.uid, day: v.day, type: v.type, year: v.year };
});

exports.redeemVoucher = functions.https.onCall(async (data, context) => {
  if(!context.auth) throw new functions.https.HttpsError('unauthenticated', 'Login erforderlich');
  const adminDoc = await db.collection('adv_admins').doc(context.auth.uid).get();
  if(!adminDoc.exists) throw new functions.https.HttpsError('permission-denied', 'Nur Admin');

  const { code } = data || {};
  if(!code) throw new functions.https.HttpsError('invalid-argument', 'code fehlt');

  const vref = db.collection('adv_vouchers').doc(code);
  return await db.runTransaction(async tx => {
    const vsnap = await tx.get(vref);
    if(!vsnap.exists) throw new functions.https.HttpsError('not-found', 'Unbekannter Code');
    const v = vsnap.data();

    const { token } = signPayload(v.uid, v.year, v.day, v.type, v.nonce);
    if(token !== v.token) throw new functions.https.HttpsError('permission-denied', 'Ungültige Signatur');
    if(v.redeemed) throw new functions.https.HttpsError('already-exists', 'Bereits eingelöst');

    tx.update(vref, { redeemed: true, redeemedAt: admin.firestore.FieldValue.serverTimestamp() });
    const uref = db.collection('adv_users').doc(v.uid);
    tx.update(uref, {
      [`rewards.${v.day}.payload.redeemed`]: true,
      [`rewards.${v.day}.payload.redeemedAt`]: admin.firestore.FieldValue.serverTimestamp()
    });
    return { ok:true, uid: v.uid, day: v.day, type: v.type };
  });
});
