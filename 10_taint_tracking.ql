import cpp
import semmle.code.cpp.dataflow.TaintTracking
import DataFlow::PathGraph

class NetworkByteSwap extends Expr{
    NetworkByteSwap () {
        exists(MacroInvocation mi|mi.getMacroName() in ["ntohs","ntohl","ntohll"]
        | mi.getExpr() = this)
    }
}
class Config extends TaintTracking::Configuration {
    Config() { this = "NetworkToMemFuncLength" }
  
    override predicate isSource(DataFlow::Node source) {
      // TODO
      source.asExpr() instanceof NetworkByteSwap
    }
    override predicate isSink(DataFlow::Node sink) {
      // TODO
      exists(FunctionCall c| sink.asExpr() = c.getArgument(2) |c.getTarget().getName() = "memcpy" ) 
    }
  }
  
  from Config cfg, DataFlow::PathNode source, DataFlow::PathNode sink
  where cfg.hasFlowPath(source, sink)
  select sink, source, sink, "Network byte swap flows to memcpy"