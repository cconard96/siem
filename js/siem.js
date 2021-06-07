/*
 *  -------------------------------------------------------------------------
 *  SIEM plugin for GLPI
 *  Copyright (C) 2019 by Curtis Conard
 *  https://github.com/cconard96/siem
 *  -------------------------------------------------------------------------
 *  LICENSE
 *  This file is part of SIEM plugin for GLPI.
 *  SIEM plugin for GLPI is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *  SIEM plugin for GLPI is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *  You should have received a copy of the GNU General Public License
 *  along with SIEM plugin for GLPI. If not, see <http://www.gnu.org/licenses/>.
 */

/* global CFG_GLPI */
(function() {
   window.SIEMPlugin = function() {
      var self = this;
      this.ajax_root = CFG_GLPI.root_doc + "/plugins/siem/ajax/";
      this.dashboard = '#siem-dashboard';

      $(document).ready(function() {

      });

      this.toggleEventDetails = function(row) {
         var id = $(row).attr('id');
         var content_row = $("#" + id + "_content");

         if (typeof content_row !== typeof undefined) {
            var hidden_attr = content_row.attr('hidden');
            if (typeof hidden_attr !== typeof undefined) {
               content_row.removeAttr('hidden');
            } else {
               content_row.attr('hidden', 'hidden');
            }
         }
      };

      this.updateSensorDropdown = function(plugin_dropdown, sensor_dropdown, linked_btn) {
         var selected_plugin = $(plugin_dropdown).val();
         $.ajax({
            type: "GET",
            url: self.ajax_root + 'getSensors.php',
            data: {
               plugins_id: selected_plugin
            },
            success: function (sensors) {
               var sensordropdown_jobj = $(sensor_dropdown);
               sensordropdown_jobj.empty().select2({
                  width: 'max-content'
               });
               if (Object.keys(sensors).length > 0) {
                  sensordropdown_jobj.removeAttr('disabled');
                  $(linked_btn).removeAttr('disabled');
               } else {
                  sensordropdown_jobj.attr('disabled', 'disabled');
                  $(linked_btn).attr('disabled', 'disabled');
               }
               $.each(sensors, function(id, name) {
                  sensordropdown_jobj.append(new Option(name, id, false, false));
               });
               sensordropdown_jobj.trigger('change');
            }
         });
      };

      this.updateServiceParamsFields = function(plugin_dropdown, sensor_dropdown) {
         var selected_plugin = $(plugin_dropdown).val();
         var selected_sensor = $(sensor_dropdown).val();

         $.ajax({
            type: "GET",
            url: self.ajax_root + 'getSensorParameters.php',
            data: {
               plugins_id: selected_plugin,
               sensor: selected_sensor
            },
            success: function (params) {
               const service_params_container = $('#service-params');
               service_params_container.empty();
               let params_table = `<table><thead><th>Name</th><th>Value</th></thead><tbody>`
               $.each(params, (id, param) => {
                  params_table += `
                     <tr><td>${param['label']}</td>
                     <td>
                        <input value="${param['default']}"/>
                     </td></tr>
                  `;
               });
               params_table += `</tbody></table>`;
               service_params_container.append(params_table);
            }
         });
      };

      this.hostCheckNow = function(hosts_id) {
         $.ajax({
            type: "POST",
            url: self.ajax_root + 'siemhost.php',
            data: {
               _check_now: true,
               hosts_id: hosts_id
            },
            success: function() {
               window.location.reload();
            }
         });
      }

      function serviceCheckNow(services_id) {

      }

      function hostScheduleDowntime(hosts_id) {

      }

      function serviceScheduleDowntime(services_id) {

      }

      this.addHostService = function(hosts_id) {
         $.ajax({
            type: "GET",
            url: self.ajax_root + 'getSiemServiceTemplates.php',
            data: {},
            success: function (servicetemplates) {
               $("<div id='add-host-form'><select class='service-template-dropdown'></select></div>").dialog({
                  modal: true,
                  title: "Add service from template",
                  open: function() {
                     var templatedropdown_jobj = $("#add-host-form .service-template-dropdown");
                     templatedropdown_jobj.empty().select2({
                        width: 'max-content'
                     });
                     if (Object.keys(servicetemplates).length > 0) {
                        templatedropdown_jobj.removeAttr('disabled');
                        //$(linked_btn).removeAttr('disabled');
                     } else {
                        templatedropdown_jobj.attr('disabled', 'disabled');
                        //$(linked_btn).attr('disabled', 'disabled');
                     }
                     $.each(servicetemplates, function(id, name) {
                        templatedropdown_jobj.append(new Option(name, id, false, false));
                     });
                     templatedropdown_jobj.trigger('change');
                  },
                  buttons: {
                     Add: function() {
                        var parentDialog = $(this);
                        var templates_id = $("#add-host-form").find("select").select2('val');
                        $.ajax({
                           type: "POST",
                           url: self.ajax_root + 'siemhost.php',
                           data: {
                              _add_service: true,
                              hosts_id: hosts_id,
                              servicetemplates_id: templates_id
                           },
                           success: function() {
                              window.location.reload();
                           },
                           complete: function() {
                              parentDialog.dialog('close');
                           }
                        });
                     }
                  }
               });
            }
         });
      }
   };
   // Always initialize this JS object to prevent needing inline JS to initialize it.
   // We will intelligently guess at which functions need to be called based on the elements on the page after it loads.
   // For example, if a #siem-dashboard element is present, we initialize and refresh the dashboard view.
    window.pluginSiem = new SIEMPlugin();
})();