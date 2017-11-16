export interface WhitelistDomain {
  domain: string | RegExp;
  paths?: Array<string | RegExp>
}
