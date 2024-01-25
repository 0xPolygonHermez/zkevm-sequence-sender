package metrics

// CallerLabel is used to point which entity is the caller of a given function
type CallerLabel string

// DiscardCallerLabel is used we want to skip measuring the execution time
const DiscardCallerLabel CallerLabel = "discard"
