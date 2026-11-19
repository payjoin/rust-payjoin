- The v1 sender and receiver no longer read a whole HTTP body into memory
  before checking its size. A body larger than its declared `Content-Length`
  or 5,333,333 bytes is refused as it arrives. When the sender refuses a
  response, it prints the command to broadcast the fallback transaction.
