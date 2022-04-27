package com.example.analyticstracker

interface AnalyticsService {

    fun logEvent(name: String, params: Map<String, Any>? = null)
}

