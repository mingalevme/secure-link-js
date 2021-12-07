export interface Now {
  now(): Date;
}

export class DateNow implements Now {
  private readonly date: Date | null;

  constructor(date?: Date) {
    this.date = date || null;
  }

  now(): Date {
    return this.date || new Date();
  }
}
