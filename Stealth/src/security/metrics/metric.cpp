#include "stdafx.h"

eMetricType Metric::GetType() {
	return METRIC_NONE;
}

eMetrics Metric::GetIndex() {
	return METRICS_NONE;
}

void Metric::OnMetric() {
	LOG_DEV("Metric with ID %i called with no OnMetric polymorphic callback!", GetType());
}

void ProcessMetric(Metric* pMetric, const char* pExtraInfo) {

	pMetric->OnMetric();
}