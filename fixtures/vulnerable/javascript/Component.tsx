// React and Angular seeds.
import React from "react";
import { DomSanitizer, SafeHtml } from "@angular/platform-browser";

export function Comment(props: { body: string }) {
  return <div dangerouslySetInnerHTML={{ __html: props.body }} />;
}

export class Preview {
  html: SafeHtml | undefined;
  constructor(private sanitizer: DomSanitizer) {}
  show(body: string) {
    this.html = this.sanitizer.bypassSecurityTrustHtml(body);
  }
}
