import { authenticator } from 'otplib';
import crypto from 'crypto';
authenticator.options = {
    step: 30,
    window: [2, 2]
};
export class TotpService {
    static generateSecret() {
        return authenticator.generateSecret();
    }
    static generateToken(secret) {
        return authenticator.generate(secret);
    }
    static verifyToken(token, secret) {
        try {
            return authenticator.verify({ token, secret });
        }
        catch (error) {
            return false;
        }
    }
    static generateOtpAuthUrl(secret, email, issuer = 'Pagandu Fintech') {
        return authenticator.keyuri(email, issuer, secret);
    }
    static generateRecoveryCodes(count = 10) {
        const codes = [];
        for (let i = 0; i < count; i++) {
            const code = crypto.randomBytes(4).toString('hex').toUpperCase();
            codes.push(code);
        }
        return codes;
    }
    static hashRecoveryCode(code) {
        return crypto.createHash('sha256').update(code.toUpperCase()).digest('hex');
    }
    static verifyRecoveryCode(code, hash) {
        const codeHash = this.hashRecoveryCode(code);
        return crypto.timingSafeEqual(Buffer.from(codeHash, 'hex'), Buffer.from(hash, 'hex'));
    }
}
