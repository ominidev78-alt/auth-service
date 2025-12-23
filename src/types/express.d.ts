import { Request } from 'express';

declare global {
  namespace Express {
    interface Request {
      id?: string;
      user?: any; // Replace with proper User interface later
      admin?: any; // Replace with proper Admin interface later
    }
  }
}
