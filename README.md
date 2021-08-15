# web

A minimal library for creating webservers in go

It is built on gorilla mux and handles lifecycle management, jwt auth (if you want), http redirect, middleware, and endpoint specification if you want it to. The goal is to eliminate the need to rewrite a lot of plumbing while allowing you to customize the server for more complex usecases.

## Why?

Because I often want to create a minimal webserver using gorilla mux and I found myself following this pattern quite a bit. I find that frameworks are often restrictive so this is not a framework. This is a library that is intended to help with basic plumbing for an http server. You can overwrite whatever you want (for example the router or middleware) with more complex logic if/when you want to.
