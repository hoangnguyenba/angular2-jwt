import { Injectable, Inject } from '@angular/core';
import {
  HttpRequest,
  HttpHandler,
  HttpEvent,
  HttpInterceptor
} from '@angular/common/http';
import { JwtHelperService } from './jwthelper.service';
import { JWT_OPTIONS } from './jwtoptions.token';
import { Observable } from 'rxjs/Observable';
import 'rxjs/add/observable/fromPromise';
import 'rxjs/add/operator/mergeMap';

@Injectable()
export class JwtInterceptor implements HttpInterceptor {
  tokenGetter: () => string | Promise<string>;
  headerName: string;
  authScheme: string;
  whitelistPredicate: (request: HttpRequest<any>) => boolean | Promise<boolean> | Observable<boolean>;
  throwNoTokenError: boolean;
  skipWhenExpired: boolean;

  constructor(
    @Inject(JWT_OPTIONS) config: any,
    public jwtHelper: JwtHelperService
  ) {
    this.tokenGetter = config.tokenGetter;
    this.headerName = config.headerName || 'Authorization';
    this.authScheme =
      config.authScheme || config.authScheme === ''
        ? config.authScheme
        : 'Bearer ';
    this.whitelistPredicate = config.whitelistPredicate || (() => true);
    this.throwNoTokenError = config.throwNoTokenError || false;
    this.skipWhenExpired = config.skipWhenExpired;
  }

  handleInterception(
    token: string,
    httpRequest: HttpRequest<any>,
    next: HttpHandler
  ) {
    let tokenIsExpired: boolean;
    let request: HttpRequest<any>;

    if (!token && this.throwNoTokenError) {
      throw new Error('Could not get token from tokenGetter function.');
    }

    if (this.skipWhenExpired) {
      tokenIsExpired = token ? this.jwtHelper.isTokenExpired(token) : true;
    }

    if (token && tokenIsExpired && this.skipWhenExpired) {
      request = httpRequest.clone();
      return next.handle(request);
    } else if (token) {
      const isWhitelisted = this.whitelistPredicate(httpRequest);

      request = httpRequest.clone({
        setHeaders: {
          [this.headerName]: `${this.authScheme}${token}`
        }
      });

      if (isWhitelisted instanceof Observable) {
        return isWhitelisted
          .mergeMap((result) => result
            ? next.handle(request)
            : next.handle(httpRequest)
          );
      } else if (isWhitelisted instanceof Promise) {
        return Observable.fromPromise(isWhitelisted)
          .mergeMap((result) => result
            ? next.handle(request)
            : next.handle(httpRequest)
          );
      } else {
        return isWhitelisted
          ? next.handle(request)
          : next.handle(httpRequest);
      }
    }
  }

  intercept(
    request: HttpRequest<any>,
    next: HttpHandler
  ): Observable<HttpEvent<any>> {
    const token: any = this.tokenGetter();

    if (token instanceof Promise) {
      return Observable.fromPromise(token).mergeMap((asyncToken: string) => {
        return this.handleInterception(asyncToken, request, next);
      });
    } else {
      return this.handleInterception(token, request, next);
    }
  }
}
