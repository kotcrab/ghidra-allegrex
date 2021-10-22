package allegrex.agent.ppsspp

import allegrex.agent.ppsspp.client.websocket.PpssppWsClient
import allegrex.agent.ppsspp.model.PpssppDebuggerObjectModel
import ghidra.dbg.DebuggerModelFactory
import ghidra.dbg.DebuggerObjectModel
import ghidra.dbg.util.ConfigurableFactory
import java.util.concurrent.CompletableFuture

@Suppress("unused")
@ConfigurableFactory.FactoryDescription(
  brief = "PPSSPP WebSocket debugger (beta)",
  htmlDetails = """Connect to a running PPSSPP instance over WebSocket.
Make sure "Allow remote debugger" is enabled in Developer tools.
Note: This integration is in beta. Please report any issues
to kotcrab/ghidra-allegrex GitHub repository"""
)
class PpssppWsDebuggerModelFactory : DebuggerModelFactory {
  @JvmField
  @ConfigurableFactory.FactoryOption("Connection Address (empty to auto-detect)")
  val connectionUrlOption: ConfigurableFactory.Property<String> =
    ConfigurableFactory.Property.fromAccessors(String::class.java, { connectionUrl }, { connectionUrl = it })

  private var connectionUrl = ""

  override fun build(): CompletableFuture<out DebuggerObjectModel> {
    val model = PpssppDebuggerObjectModel(PpssppWsClient(connectionUrl))
    return model.start().thenApply { model }
  }
}
