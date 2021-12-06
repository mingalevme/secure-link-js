export interface Now {
  now(): Date;
}

export class DateNow implements Now {
  private readonly date: Date;

  constructor(date?: Date) {
    this.date = date;
  }

  now(): Date {
    return this.date || new Date();
  }
}
