// Package logging implements attribute-based logging. Log entries
// consist of timestamps, an actor and event string, and a mapping of
// string key-value attribute pairs. For example,
//
//   log.Error("serialiser", "failed to open file",
//             map[string]string{
//                     "error": err.Error(),
//                     "path": "data.bin",
//             })
//
// This produces the output message
//
//   [2016-04-01T15:04:30-0700] [ERROR] [actor:serialiser event:failed to open file] error=is a directory path=data.bin
//
package logging
