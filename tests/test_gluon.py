#!/usr/bin/env python3
import sys
from driver import Node


def test_reconfigure():
    a = Node()

    a.succeed("gluon-reconfigure")

