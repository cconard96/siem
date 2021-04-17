<?php
/**
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

use Twig\Extension\AbstractExtension;
use Twig\TwigFilter;
use Twig\TwigFunction;

class PluginSiemTwigExtension extends AbstractExtension {

   public function initRuntime(\Twig\Environment $environment)
   {
      // No-op
   }

   public function getGlobals()
   {
      // No-op
   }

   public function getName()
   {
      // No-op
   }

   public function getFunctions()
   {
      return [
         new TwigFunction('__', [$this, '__']),
         new TwigFunction('_n', [$this, '_n']),
         new TwigFunction('_x', [$this, '_x']),
         new TwigFunction('_nx', [$this, '_nx']),
      ];
   }

   /**
    * @param string $message
    * @param string $domain
    * @return string
    * @since 1.0.0
    * @see __()
    */
   public function __(string $message, string $domain = 'siem'): string
   {
      return __($message, $domain);
   }

   /**
    * @param string $sing
    * @param string $plural
    * @param int $nb
    * @param string $domain
    * @return string
    * @see _n()
    */
   public function _n(string $sing, string $plural, int $nb, string $domain = 'siem'): string
   {
      return _n($sing, $plural, $nb, $domain);
   }

   /**
    * @param string $ctx
    * @param string $message
    * @param string $domain
    * @return string
    * @see _x()
    */
   public function _x(string $ctx, string $message, string $domain = 'siem'): string
   {
      return _x($ctx, $message, $domain);
   }

   /**
    * @param string $ctx
    * @param string $sing
    * @param string $plural
    * @param int $nb
    * @param string $domain
    * @return string
    * @see _nx()
    */
   public function _nx(string $ctx, string $sing, string $plural, int $nb, string $domain = 'siem'): string
   {
      return _nx($ctx, $sing, $plural, $nb, $domain);
   }
}