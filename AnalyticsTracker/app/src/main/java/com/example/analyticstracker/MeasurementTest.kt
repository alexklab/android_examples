package com.example.analyticstracker

import com.example.analyticstracker.proxy.AnalyticsProxy
import kotlin.system.measureNanoTime

object MeasurementTest {

    interface Tracker {

        @EventName("singleEvent")
        fun singleEvent()

        @EventName("eventWithParams")
        fun eventWithParams(
            @Param("p1") p1: Int,
            @Param("p2") p2: Double,
            @Param("p3") p3: String
        )
    }

    class MockedAnalyticsService : AnalyticsService {
        override fun logEvent(name: String, params: Map<String, Any>?) {
            if (params.isNullOrEmpty()) {
                print(name)
            } else {
                print("$name $params")
            }
        }
    }

    @JvmStatic
    fun main(vararg args: String) {

        val service = MockedAnalyticsService()

        val tracker = AnalyticsProxy(service, false).create<Tracker>()

        repeat(15) {
            println(" " + measureNanoTime { tracker.singleEvent() })
        }



    }
}