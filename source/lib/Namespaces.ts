export enum Paths {
  INVOKE = 'invoke',
  PREDICTION = 'prediction',
}
export enum Status {
  SUCCEED = 'SUCCEED',
  FAIL = 'FAIL',
}

export type PathExtract = {
  first: string;
  second: string;
  third: string;
};

export type ApiResponse = {
  status: Status;
  statusCode: number;
  message: any;
};

export type MailMessage = {
  body: string;
  to: string;
  title: string;
};
