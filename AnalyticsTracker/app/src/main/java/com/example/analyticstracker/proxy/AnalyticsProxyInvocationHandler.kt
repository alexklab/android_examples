package com.example.analyticstracker.proxy

import com.example.analyticstracker.AnalyticsService
import com.example.analyticstracker.EventName
import com.example.analyticstracker.Param
import java.lang.reflect.InvocationHandler
import java.lang.reflect.Method


class AnalyticsProxyInvocationHandler(
    private val analyticsService: AnalyticsService
) : InvocationHandler {

    override fun invoke(proxy: Any, method: Method, args: Array<out Any>?): Any {
        val annotations = method.declaredAnnotations
        val eventName = annotations.firstNotNullOfOrNull { it as? EventName }
            ?.value ?: return Unit

        if (args.isNullOrEmpty()) {
            analyticsService.logEvent(eventName, params = null)
        } else {

            val params = hashMapOf<String, Any>()

            method.parameters.forEachIndexed { index, param ->
                param.annotations
                    .firstNotNullOfOrNull { it as? Param }
                    ?.let { params += it.value to args[index] }
            }

            analyticsService.logEvent(eventName, params)
        }
        return Unit
    }
}