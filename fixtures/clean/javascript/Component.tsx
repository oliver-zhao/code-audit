// Safe React and Angular counterparts.
import React from "react";
import DOMPurify from "dompurify";

export function Comment(props: { body: string }) {
  return <div>{props.body}</div>;
}

export function Rich(props: { body: string }) {
  return <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(props.body) }} />;
}
