/*
Copyright 2021 The Katanomi Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1alpha1

import (
	"encoding/json"

	cloudevents "github.com/cloudevents/sdk-go/v2"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

type CloudEvent struct {
	ID      string `json:"id,omitempty"`
	Source  string `json:"source,omitempty"`
	Subject string `json:"subject,omitempty"`
	// Type of event
	Type string `json:"type,omitempty"`
	// Data event payload
	Data            string                          `json:"data,omitempty"`
	Time            metav1.Time                     `json:"time,omitempty"`
	SpecVersion     string                          `json:"specversion,omitempty"`
	DataContentType string                          `json:"datacontenttype,omitempty"`
	Extensions      map[string]runtime.RawExtension `json:"extensions,omitempty"`
}

func (evt *CloudEvent) From(event cloudevents.Event) *CloudEvent {
	evt.ID = event.ID()
	evt.Source = event.Source()
	evt.Data = string(event.Data())
	evt.Subject = event.Subject()
	evt.DataContentType = event.DataContentType()
	evt.Type = event.Type()
	evt.SpecVersion = event.SpecVersion()
	evt.Time = metav1.NewTime(event.Time())
	for key, val := range event.Extensions() {
		if evt.Extensions == nil {
			evt.Extensions = map[string]runtime.RawExtension{}
		}
		bts, _ := json.Marshal(val)
		evt.Extensions[key] = runtime.RawExtension{
			Raw: bts,
		}
	}
	return evt
}