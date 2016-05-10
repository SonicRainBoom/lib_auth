'use strict';

import {SRBEvent} from 'lib_srbevent';
import {KeyStore} from 'lib_crypto';
export {KeyStore};// from 'lib_crypto';
import jwt = require('jsonwebtoken');

export type Timestamp = number;

export interface JWT {
  iat?: Timestamp
  nbf?: Timestamp
  exp?: Timestamp
  aud?: string | string[]
  iss?: string
  sub?: string
}

export interface enrichedJWT extends JWT{
  type?: string
  dummy?: boolean
  payload?: {}
  roles?: string[]
}

/**
 * TrustStore-interface.
 * Compatible with any KV-Store implementation that returns null/undefined
 * on ::get() if the key cannot found.
 * All calls to relevant functions are to be synchronous!
 * E.g. ES6 Map, most redis implementations
 */
export interface ITrustStore {
  get(fingerprint: string): string
  set(fingerprint: string, publicKey: string): any
}

/**
 * Used in the client to authenticate to a specific SRB-instance.
 */
export class ClientAuthentication {
  protected type = 'client';

  constructor(private authToken: string) {
    //TODO: Implement client auth.
  }
}

/**
 * Extended upon by SRBInstanceAuthentication and CentralInstanceAuthentication.
 */
export class ServerAuthentication {
  protected type           = 'generic';
  protected targetAudience = ['generic'];

  constructor(private keyStore: KeyStore, private trustStore: ITrustStore) {
    // Make sure the signing key is in the truststore to be able to verify own
    // tokens
    if (!this.trustStore.get(keyStore.publicFingerprint)) {
      this.trustStore.set(
        keyStore.publicFingerprint,
        keyStore.exportPublicKey()
      );
    }
  }

  updateKeyStore = (keyStore: KeyStore): void => {
    this.keyStore = keyStore;
  };

  addToTrustStore(fingerprint: string, publicPEM: string): void {
    this.trustStore.set(fingerprint, publicPEM);
  }

  extractIssuer = (token: string) => {
    let decoded = jwt.decode(token);
    return decoded.iss || false;
  };

  extractTokenType = (token: string) => {
    let decoded = jwt.decode(token);
    return decoded.type || false;
  };

  verifyToken = (token: string,
                 forcedIssuer: string,
                 forcedTokenType: string): enrichedJWT => {
    let issuer: string    = forcedIssuer || this.extractIssuer(token);
    let tokenType: string = forcedTokenType || this.extractTokenType(token);

    if (!this.trustStore.get(issuer)) {
      throw new Error('Issuer not in truststore');
    }

    let pubKey = this.trustStore.get(issuer);
    try {
      let validatedToken = <enrichedJWT> jwt.verify(
        token,
        pubKey,
        {audience: this.type}
      );

      if (validatedToken.type != tokenType) {
        SRBEvent.error(new Error('tokenType invalid!'));
        return null;
      }

      return validatedToken;
    } catch (err) {
      SRBEvent.error(err);
      return null;
    }
  };

  issueToken = (subject: string,
                content?: enrichedJWT,
                roles?: string[],
                expiresIn?: string|number,
                type?: string): Promise<string> => {
    content             = content || {};
    content.type        = type || this.type;
    content.roles       = roles || [];
    let properties: any = {
      issuer   : this.keyStore.publicFingerprint,
      algorithm: 'RS512',
      subject  : subject,
      notBefore: 0,
      audience : this.targetAudience
    };
    if (expiresIn) {
      properties['expiresIn'] = expiresIn
    }
    return new Promise<string>(
      (resolve, reject) => {
        return jwt.sign(
          content || {},
          this.keyStore.exportPrivateKey(),
          properties,
          (err: Error, token: string) => {
            if (err) {
              reject(err)
            } else {
              resolve(token);
            }
          }
        );
      }
    )
  }
}

/**
 * Used in SRB-Central to validate calls from SRB-instances.
 */
export class CentralInstanceAuthentication extends ServerAuthentication {
  protected type           = 'central';
  protected targetAudience = ['central', 'srb'];

  constructor(keyStore: KeyStore, trustStore: ITrustStore) {
    super(keyStore, trustStore);
  }
}

/**
 * Used in a SRB-instance to authenticate to a central or client.
 */
export class SRBInstanceAuthentication extends ServerAuthentication {
  protected type           = 'srb';
  protected targetAudience = ['srb', 'central'];

  constructor(keyStore: KeyStore, trustStore: ITrustStore) {
    super(keyStore, trustStore);
  }
}
