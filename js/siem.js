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

(function() {
   window.SIEMPlugin = function() {
      var self = this;
      this.ajax_root = CFG_GLPI.root_doc + "/plugins/siem/ajax/";
      this.dashboard = '#siem-dashboard';

      $(document).ready(function() {
         if ($(self.dashboard).length > 0) {
            self.refreshDashboard();
         }
      });

      var buildDashboardDeck = function(cards) {
         $(self.dashboard).empty();
         var content = "<div class='container-fluid content'>";
         content += "<h2 class='text-center'>Event Monitoring Dashboard</h2>";
         content += "<p class='text-center'>"+new Date()+"</p>";
         content += "<div class='siem-decks'>";
         $.each(cards, function(r_index, row) {
            content += "<div class='siem-deck card-deck'>";
            $.each(row, function(c_index, card) {
               var card_classes = ['siem-card', 'card', 'text-center', 'card-'+card.type];
               if (card.extra_card_classes !== undefined) {
                  card_classes.concat(card.extra_card_classes);
               }
               content += "<div class='"+card_classes.join(' ')+"'>";
               content += "<div class='card-header'><p class=''>"+card.title+"</p></div>";
               content += "<div class='card-body'>";
               content += buildCardBody(card);
               content += "</div></div>";
            });
            content += "</div>";
         });
         content += "</div></div>";
         $(content).appendTo($(self.dashboard));
      };

      var buildCardBody = function(card) {
         var content = '';
         if (card.type === 'counter') {
            return "<p>"+card.value+"</p>";
         } else if (card.type === 'table') {
            content += "<table class='w-100'><thead>";
            $.each(card.headers, function(i, header) {
               content += "<th>"+header+"</th>";
            });
            content += "</thead><tbody>";
            $.each(card.rows, function(i, row) {
               content += "<tr>";
               $.each(row, function(i2, cell) {
                  content += "<td class='"+(cell['class'] || '')+"'>" + cell.value + "</td>";
               });
               content += "</tr>";
            });
            content += "</tbody></table>";
         } else if (card.type === 'table-v') {
            content += "<table class='w-100'>";
            $.each(card.headers, function(i, header) {
               var cell = card.rows[i];
               content += "<tr class='"+(cell['class'] || '')+"'>";
               content += "<th class=''text-center>"+header+"</th>";
               content += "<td class='text-left'>"+cell.value+"</td>";
               content += "</tr>";
            });
            content += "</table>";
         } else {
            return "<p>"+card.value+"</p>";
         }
         return content;
      };

      self.refreshDashboard = function() {
         var form = $(self.dashboard+' .siem-toolbar');
         var get_data = form.serialize();
         $.ajax({
            type: "GET",
            url: self.ajax_root + 'siemdashboard.php',
            data: get_data,
            success: function (cards) {
               buildDashboardDeck(cards);
            }
         });
      };

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

      this.hostCheckNow = function(hosts_id) {
         $.ajax({
            type: "POST",
            url: self.ajax_root + 'siemhost.php',
            data: {
               _check_now: true,
               hosts_id: hosts_id
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
   // Always initialize this JS object to prevent needing inline JS to intialize it.
   // We will intelligently guess at which functions need to be called based on the elements on the page after it loads.
   // For example, if a #siem-dashboard element is present, we initialize and refresh the dashboard view.
    window.pluginSiem = new SIEMPlugin();
})();