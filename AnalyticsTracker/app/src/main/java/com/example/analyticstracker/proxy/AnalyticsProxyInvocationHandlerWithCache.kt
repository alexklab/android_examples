package com.example.analyticstracker.proxy

import com.example.analyticstracker.AnalyticsService
import java.lang.IllegalArgumentException
import java.lang.reflect.InvocationHandler
import java.lang.reflect.Method

class AnalyticsProxyInvocationHandlerWithCache(
    private val analyticsService: AnalyticsService
) : InvocationHandler {

    private val eventFactories: MutableMap<Method, EventFactory> = mutableMapOf()

    override fun invoke(proxy: Any, method: Method, args: Array<out Any>?): Any {
        val factory = eventFactories.getOrPut(method) { newEventFactory(method) ?: return Unit }
        analyticsService.logEvent(factory.name, factory.buildParams(args))
        return Unit
    }

    private fun newEventFactory(method: Method): EventFactory? {
        val annotations = method.declaredAnnotations
        val eventName = annotations.firstNotNullOfOrNull { it as? EventName }?.value
            ?: return null

        val argNames = method.parameters.map { param ->
            param.annotations.firstNotNullOfOrNull { it as? Param }?.value
        }

        return EventFactory(eventName, argNames)
    }

    private class EventFactory(
        val name: String,
        private val paramNames: List<String?>
    ) {

        fun buildParams(args: Array<out Any>?): Map<String, Any>? {
            if (args.isNullOrEmpty()) return null

            if (paramNames.size != args.size) throw IllegalArgumentException("Param names should be the same size with args")

            val params = hashMapOf<String, Any>()
            paramNames.forEachIndexed { index, name ->
                if (name != null) {
                    params += name to args[index]
                }
            }
            return params
        }
    }
}