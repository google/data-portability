/*
 * Copyright 2018 The Data Transfer Project Authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.dataportabilityproject.transfer.rememberthemilk.model.tasks;

import com.fasterxml.jackson.xml.annotate.JacksonXmlProperty;
import com.google.common.base.Joiner;
import java.util.ArrayList;
import java.util.List;

/** A list of one or more {@link Task} contained in a {@link TaskSeries}. */
public class TaskList {

  @JacksonXmlProperty(isAttribute = true, localName = "id")
  public int id;

  @JacksonXmlProperty(localName = "taskseries")
  public List<TaskSeries> taskseries;

  // Needed if there's only 1 element (with no wrapper)
  public void setTaskseries(TaskSeries singleSeries) {
    this.taskseries = new ArrayList<>();
    taskseries.add(singleSeries);
  }

  @Override
  public String toString() {
    return String.format(
        "(list id=%d children:[%s])",
        id, (taskseries == null || taskseries.isEmpty()) ? "" : Joiner.on("\n").join(taskseries));
  }
}